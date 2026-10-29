//! A per-crate model of functions and the security-relevant facts about them.
//!
//! Rules use the model to answer questions such as "does this exported
//! contract function, or anything it calls, perform `require_auth`?" without
//! each rule re-implementing call-graph traversal.

use std::collections::{BTreeSet, HashMap, HashSet};

use syn::visit::Visit;
use syn::{Attribute, Block, Expr, Signature};

use crate::project::Project;
use crate::syntax::{
    attr_is, call_name, idents, is_assert_macro, macro_args, macro_name, resolved_idents, storage_op, words, Bindings,
    Span, StorageOpKind, StorageTier,
};

mod facts;
mod graph;
mod items;
mod queries;

use facts::collect_facts;
pub use facts::key_id;
#[cfg(test)]
use items::file_module_path;
pub use items::resolve_const_key;
use items::OwnFns;

/// How deep helper chains are followed by path-sensitive queries.
const MAX_DEPTH: usize = 16;

/// Index of a function in [`CrateModel::fns`].
pub type FnId = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FnKind {
    /// A function exported by a `#[contractimpl]` block (callable on-chain).
    ContractExport { contract: String, via_trait: Option<String> },
    /// A method in an ordinary `impl` block (or a non-exported contractimpl fn).
    Method { self_ty: String, has_self: bool },
    /// A free function.
    Free,
}

/// A function definition anywhere in the crate.
#[derive(Debug, Clone)]
pub struct FnDef<'a> {
    pub name: String,
    pub kind: FnKind,
    /// Index into [`Project::files`].
    pub file: usize,
    pub sig: &'a Signature,
    pub block: &'a Block,
    pub attrs: &'a [Attribute],
    /// Span of the function name.
    pub name_span: Span,
    /// Module path inside the crate: file modules (`src/a/b.rs` → `a::b`) plus inline `mod` blocks.
    pub module: Vec<String>,
    /// Self type of the enclosing `impl`, if any.
    pub self_ty: Option<String>,
    /// Trait of the enclosing `impl Trait for T` or the trait declaring a default method.
    pub trait_name: Option<String>,
    /// `true` for functions of a local dependency crate, modelled only so calls into it resolve.
    pub foreign: bool,
}

impl FnDef<'_> {
    pub fn is_contract_export(&self) -> bool {
        matches!(self.kind, FnKind::ContractExport { .. })
    }

    /// Typed parameters as `(name, type)` pairs, excluding `self`.
    pub fn params(&self) -> Vec<(String, &syn::Type)> {
        self.sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(pt) => crate::syntax::pat_ident(&pt.pat).map(|n| (n, &*pt.ty)),
                syn::FnArg::Receiver(_) => None,
            })
            .collect()
    }

    /// `true` if any parameter's type mentions `Address`.
    pub fn takes_address(&self) -> bool {
        self.params().iter().any(|(_, ty)| idents(*ty).iter().any(|i| i == "Address"))
    }
}

/// A storage write (`set`, `remove`, `update`).
#[derive(Debug, Clone)]
pub struct StateWrite {
    pub span: Span,
    pub kind: StorageOpKind,
    pub tier: Option<StorageTier>,
    /// Identifiers naming the key (enum/struct path, symbol literal), excluding
    /// argument values. See [`crate::syntax::key_names`].
    pub key_idents: Vec<String>,
    /// `true` when the key is constructed with arguments, e.g. `DataKey::Balance(addr)`.
    pub key_is_parameterised: bool,
    /// The key expression as written (after resolving a local variable once).
    pub key_text: String,
    /// Lowercase local names (parameters or locals) used inside the key, e.g. `user` in
    /// `DataKey::Balance(user.clone())`.
    pub key_locals: Vec<String>,
    /// Lowercase locals the stored value is built from, following local bindings
    /// (`let v = Allowance { amount, .. }; set(&k, &v)` → `amount`, `v`).
    pub value_locals: Vec<String>,
    /// The stored value is computed by subtraction (`b - amount`, `b.checked_sub(amount)`).
    pub value_decreasing: bool,
}

impl StateWrite {
    /// Lowercase words of all key names (`DataKey::TotalSupply` → `data key total supply`).
    pub fn key_words(&self) -> Vec<String> {
        self.key_idents.iter().flat_map(|i| words(i)).collect()
    }

    /// Lowercase words of the most specific key name: the enum variant, struct
    /// name or symbol (`GovernorKey::OperationId(..)` → `operation id`).
    pub fn key_variant_words(&self) -> Vec<String> {
        self.key_idents.last().map(|i| words(i)).unwrap_or_default()
    }
}

/// A call to another function.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub name: String,
    pub span: Span,
    /// Method-call syntax (`x.f()`) rather than path syntax (`f()`, `Self::f()`).
    pub is_method: bool,
    /// For path calls, the segment before the name: `a` in `a::f()`, `Self` in `Self::f()`,
    /// `Trait` in `<T as Trait>::f()`.
    pub qualifier: Option<String>,
    /// Arguments in order (receiver excluded for method calls).
    pub args: Vec<CallArg>,
    /// Call appears inside a condition (`if`, `match`, `assert!` …).
    pub in_condition: bool,
    /// Call runs on only some paths: inside an `if` / `match` arm or a `for` / `while` body.
    pub in_branch: bool,
    /// The callee's name looks like an authorization helper (`require_admin`, `check_owner_auth`).
    /// Trusted only when the crate does not define the helper; otherwise its body is checked.
    pub auth_named: bool,
}

/// Which parameters a function authorizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectAuth {
    /// Indices (into [`FnDef::params`]) of parameters on which `require_auth` is called,
    /// directly or by a helper they are passed to.
    pub params: BTreeSet<usize>,
    /// Some authorization targets something other than a parameter: a stored admin,
    /// an auth helper whose body is unknown, or an access-control attribute.
    pub other: bool,
}

/// A storage write that decreases a value keyed by parameters of the queried function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Debit {
    /// The write, or the call leading to it.
    pub span: Span,
    /// Indices of the queried function's parameters used in the key.
    pub key_params: BTreeSet<usize>,
}

/// One argument of a call.
#[derive(Debug, Clone, Default)]
pub struct CallArg {
    /// The local or parameter passed, with `&`, `.clone()` and similar stripped.
    pub local: Option<String>,
    /// The argument is computed by subtraction (`balance - amount`).
    pub decreasing: bool,
    /// Lowercase locals the argument is built from, following local bindings
    /// (`balance.checked_add(amount)` → `amount`, `balance`, …).
    pub mentions: Vec<String>,
    /// Storage-key family the argument names (`&DataKey::Did(id)` → `DataKey::Did`), if any; see [`key_id`].
    pub key: Option<String>,
}

/// How reliably a function performs an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthStatus {
    /// No authorization on any path.
    Never,
    /// Authorization happens on some paths only (e.g. inside an `if`).
    Sometimes,
    /// Authorization happens on every path that reaches the end of the function.
    Always,
}

/// Security-relevant facts collected directly from one function body.
#[derive(Debug, Clone, Default)]
pub struct FnFacts {
    /// Authorization checks that run on every path: `require_auth` /
    /// `require_auth_for_args`, configured `auth-functions` and auth macros.
    pub auth: Vec<Span>,
    /// Authorization checks that run on some paths only (inside a branch or loop body).
    pub cond_auth: Vec<Span>,
    /// Receivers of `require_auth` / `require_auth_for_args` calls, when they are plain
    /// locals or parameters (`from` in `from.require_auth()`). `None` for other receivers.
    pub auth_subjects: Vec<Option<String>>,
    /// `require_auth_for_args` calls: span, receiver (when a plain local) and the
    /// lowercase local names mentioned in the argument list.
    pub auth_for_args: Vec<(Span, Option<String>, Vec<String>)>,
    /// The function carries an access-control attribute such as `#[only_owner]`.
    pub auth_attr: bool,
    pub state_writes: Vec<StateWrite>,
    pub storage_reads: Vec<Span>,
    /// Most specific key name of each `get` (`DataKey::Members` → `Members`), when known.
    pub read_keys: Vec<String>,
    /// Token transfers whose source is the contract itself.
    pub outflows: Vec<Span>,
    /// Contract upgrades: `update_current_contract_wasm` and `update_current_contract`.
    pub upgrades: Vec<Span>,
    /// Soroban event publications: `env.events().publish(..)`.
    pub event_publishes: Vec<Span>,
    /// TTL extensions by tier: `storage().<tier>().extend_ttl(..)`; the deployer's
    /// `extend_ttl_for_contract_instance` / `extend_ttl` count as instance.
    pub ttl_extends: Vec<Option<StorageTier>>,
    /// Key family extended by each entry of `ttl_extends` (see [`key_id`]); `None` when it is
    /// unknown (a `key` parameter of a generic helper) or the whole instance.
    pub ttl_extend_keys: Vec<Option<String>>,
    /// For each entry of `ttl_extends`, the plain local or parameter used as the key
    /// (`extend_ttl(key, ..)` in a helper), so callers can supply the key name.
    pub ttl_extend_key_locals: Vec<Option<String>>,
    /// Checks for existing state (`has`, or a `get` used in a condition).
    pub init_guards: Vec<Span>,
    /// Key checked by each entry of `init_guards` (most specific name), when known.
    pub init_guard_keys: Vec<Option<String>>,
    pub calls: Vec<CallSite>,
    /// Local names whose `.len()` is compared in a condition (`if items.len() >= MAX`).
    pub len_bounds: Vec<String>,
}

/// Options influencing fact collection.
#[derive(Debug, Clone, Default)]
pub struct ModelOptions {
    /// Additional function or macro names that should count as an authorization check.
    pub auth_functions: Vec<String>,
}

/// Attribute macros that enforce access control (OpenZeppelin Stellar and similar).
const AUTH_ATTRIBUTES: &[&str] = &["only_owner", "only_admin", "only_role", "has_role", "has_any_role", "only_roles"];

fn is_auth_attr(attr: &Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .map(|s| {
            let n = s.ident.to_string();
            AUTH_ATTRIBUTES.contains(&n.as_str()) || n.starts_with("only_")
        })
        .unwrap_or(false)
}

/// Heuristic: does a function name look like an authorization helper?
/// Matches e.g. `require_admin_auth`, `enforce_owner_auth`, `ensure_role`, `check_auth`.
pub fn is_auth_helper_name(name: &str, extra: &[String]) -> bool {
    if extra.iter().any(|e| e == name) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "__check_auth" {
        return false;
    }
    let prefixes = ["require", "enforce", "ensure", "assert", "check", "verify", "only"];
    let has_prefix = prefixes.iter().any(|p| lower.starts_with(p));
    has_prefix
        && (lower.contains("auth") || lower.contains("role") || lower.contains("owner") || lower.contains("admin"))
}

/// Function model for one crate.
#[derive(Debug)]
pub struct CrateModel<'a> {
    pub crate_id: usize,
    pub fns: Vec<FnDef<'a>>,
    pub facts: Vec<FnFacts>,
    by_name: HashMap<String, Vec<FnId>>,
    /// Key names of crate-level `const` / `static` items (`const KEY: Symbol =
    /// symbol_short!("ADMIN")` → `KEY` ↦ `["ADMIN"]`), used to resolve storage keys.
    pub consts: HashMap<String, Vec<String>>,
    graph: graph::CallGraph,
    cache: graph::QueryCache,
}

/// The place where a transitive property was found, seen from the queried function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// Span inside the queried function: the operation itself, or the call that leads to it.
    pub span: Span,
    /// Names of helper functions traversed, outermost first. Empty for a direct hit.
    pub via: Vec<String>,
}

impl<'a> CrateModel<'a> {
    /// Builds models for every crate in the project.
    pub fn build_all(project: &'a Project, opts: &ModelOptions) -> Vec<CrateModel<'a>> {
        // Analyse each crate's own functions once; dependency crates are then shared
        // (cloned) into every crate that uses them instead of being re-analysed.
        let n = project.crates.len().max(1);
        let own: Vec<OwnFns<'a>> = (0..n).map(|id| OwnFns::collect(project, id, opts)).collect();
        (0..n).map(|id| CrateModel::assemble(project, id, &own)).collect()
    }

    pub fn build(project: &'a Project, crate_id: usize, opts: &ModelOptions) -> Self {
        let n = project.crates.len().max(1);
        let own: Vec<OwnFns<'a>> = (0..n).map(|id| OwnFns::collect(project, id, opts)).collect();
        CrateModel::assemble(project, crate_id, &own)
    }

    fn assemble(project: &'a Project, crate_id: usize, own: &[OwnFns<'a>]) -> Self {
        let mut fns = own[crate_id].fns.clone();
        let mut facts = own[crate_id].facts.clone();
        // Helpers from local dependency crates (`common::require_admin`), so calls into a
        // shared library crate in the same workspace are followed. Their module paths are
        // prefixed with the crate name.
        let deps = project.crates.get(crate_id).map(|c| c.local_deps.clone()).unwrap_or_default();
        for (i, c) in project.crates.iter().enumerate() {
            let Some(name) = c.rust_name() else { continue };
            if i == crate_id || !deps.contains(&name) {
                continue;
            }
            for (f, fx) in own[i].fns.iter().zip(&own[i].facts) {
                let mut f = f.clone();
                f.module.insert(0, name.clone());
                f.foreign = true;
                // Exports of a dependency are not this crate's contract interface.
                if let FnKind::ContractExport { contract, .. } = &f.kind {
                    f.kind = FnKind::Method { self_ty: contract.clone(), has_self: false };
                }
                fns.push(f);
                facts.push(fx.clone());
            }
        }
        let mut by_name: HashMap<String, Vec<FnId>> = HashMap::new();
        for (i, f) in fns.iter().enumerate() {
            by_name.entry(f.name.clone()).or_default().push(i);
        }
        let n = fns.len();
        let mut model = CrateModel {
            crate_id,
            fns,
            facts,
            by_name,
            consts: own[crate_id].consts.clone(),
            graph: graph::CallGraph::default(),
            cache: graph::QueryCache::new(n),
        };
        model.graph.edges = (0..n)
            .map(|id| model.facts[id].calls.iter().map(|call| model.resolve_uncached(id, call)).collect())
            .collect();
        model
    }

    /// Functions defined in a given file.
    pub fn fns_in_file(&self, file: usize) -> impl Iterator<Item = (FnId, &FnDef<'a>)> {
        self.fns.iter().enumerate().filter(move |(_, f)| f.file == file && !f.foreign)
    }

    /// Functions with the given name.
    pub fn by_name(&self, name: &str) -> &[FnId] {
        self.by_name.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Crate functions a call site in `caller` may refer to.
    ///
    /// Candidates are found by name, then narrowed by the call's qualifier
    /// (`a::f` → functions in module `a` or on type/trait `a`, `Self::f` → the
    /// caller's impl) or, for unqualified calls, by the caller's module. When
    /// narrowing leaves nothing (e.g. a `use` alias), all same-named candidates
    /// are kept, so resolution stays conservative.
    pub fn resolve(&self, caller: FnId, call: &CallSite) -> Vec<FnId> {
        // Call sites of the model itself were resolved when it was built.
        if let Some(edges) = self.graph.edges.get(caller) {
            if let Some(i) = self.facts[caller].calls.iter().position(|c| std::ptr::eq(c, call)) {
                return edges[i].clone();
            }
        }
        self.resolve_uncached(caller, call)
    }

    /// Callees of call site `index` of `caller`, as resolved when the model was built.
    pub fn callees(&self, caller: FnId, index: usize) -> &[FnId] {
        self.graph.edges.get(caller).and_then(|e| e.get(index)).map(Vec::as_slice).unwrap_or(&[])
    }

    fn resolve_uncached(&self, caller: FnId, call: &CallSite) -> Vec<FnId> {
        let all: Vec<FnId> = self
            .by_name(&call.name)
            .iter()
            .copied()
            .filter(|&id| {
                if call.is_method {
                    matches!(self.fns[id].kind, FnKind::Method { has_self: true, .. })
                } else {
                    true
                }
            })
            .collect();
        if all.len() < 2 {
            return all;
        }
        let from = &self.fns[caller];
        // A call qualified with a dependency crate's name (`common::f`) refers to its root module.
        if let Some(q) = call.qualifier.as_deref() {
            let in_dep_root: Vec<FnId> = all
                .iter()
                .copied()
                .filter(|&id| self.fns[id].foreign && self.fns[id].module.len() == 1 && self.fns[id].module[0] == q)
                .collect();
            if !in_dep_root.is_empty() {
                return in_dep_root;
            }
        }
        // Otherwise prefer this crate's own functions over same-named dependency helpers.
        let own: Vec<FnId> = all.iter().copied().filter(|&id| self.fns[id].foreign == from.foreign).collect();
        let all = if own.is_empty() { all } else { own };
        if all.len() < 2 {
            return all;
        }
        let narrowed: Vec<FnId> = match call.qualifier.as_deref() {
            Some("Self") => all.iter().copied().filter(|&id| self.fns[id].self_ty == from.self_ty).collect(),
            Some("crate") => all.iter().copied().filter(|&id| self.fns[id].module.is_empty()).collect(),
            Some("self") => all.iter().copied().filter(|&id| self.fns[id].module == from.module).collect(),
            Some("super") => {
                let parent = &from.module[..from.module.len().saturating_sub(1)];
                all.iter().copied().filter(|&id| self.fns[id].module == parent).collect()
            }
            Some(q) => all
                .iter()
                .copied()
                .filter(|&id| {
                    let f = &self.fns[id];
                    f.module.last().is_some_and(|m| m == q)
                        || f.self_ty.as_deref() == Some(q)
                        || f.trait_name.as_deref() == Some(q)
                })
                .collect(),
            None if call.is_method => match &from.self_ty {
                Some(ty) => all.iter().copied().filter(|&id| self.fns[id].self_ty.as_ref() == Some(ty)).collect(),
                None => vec![],
            },
            None => all
                .iter()
                .copied()
                .filter(|&id| self.fns[id].module == from.module && self.fns[id].self_ty.is_none())
                .collect(),
        };
        if narrowed.is_empty() {
            all
        } else {
            narrowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo::CrateInfo;

    fn project(src: &str) -> Project {
        Project::from_sources([("lib.rs", src)], CrateInfo::default(), false)
    }

    #[test]
    fn classifies_exports() {
        let p = project(
            r#"
            #[contractimpl]
            impl C { pub fn a(e: Env) {} fn b(e: Env) {} }
            #[contractimpl]
            impl Tr for C { fn c(e: Env) {} }
            impl C { pub fn d(&self) {} }
            fn e() {}
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let exports: Vec<_> = m.fns.iter().filter(|f| f.is_contract_export()).map(|f| f.name.as_str()).collect();
        assert_eq!(exports, vec!["a", "c"]);
        assert_eq!(m.fns.len(), 5);
    }

    #[test]
    fn transitive_auth_and_writes() {
        let p = project(
            r#"
            fn check(e: &Env) { let a: Address = e.storage().instance().get(&K::Admin).unwrap(); a.require_auth(); }
            fn write(e: &Env, v: i128) { e.storage().persistent().set(&K::V, &v); }
            #[contractimpl]
            impl C {
                pub fn guarded(e: Env, v: i128) { check(&e); write(&e, v); }
                pub fn open(e: Env, v: i128) { write(&e, v); }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let id = |n: &str| m.by_name(n)[0];
        assert!(m.performs_auth(id("guarded")));
        assert!(!m.performs_auth(id("open")));
        let w = m.witness(id("open"), &|_, f| f.state_writes.first().map(|w| w.span)).unwrap();
        assert_eq!(w.via, vec!["write".to_string()]);
    }

    #[test]
    fn init_guards() {
        let p = project(
            r#"
            fn is_init(e: &Env) -> bool { e.storage().instance().has(&K::Admin) }
            #[contractimpl]
            impl C {
                pub fn a(e: Env) { if is_init(&e) { panic!() } e.storage().instance().set(&K::Admin, &1); }
                pub fn b(e: Env) { assert!(e.storage().instance().get::<_, bool>(&K::Init).is_none()); }
                pub fn c(e: Env) { e.storage().instance().set(&K::Admin, &1); }
                pub fn d(e: Env) { let cur = e.storage().instance().get::<_, u32>(&K::A); if cur.is_some() { panic!() } }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let id = |n: &str| m.by_name(n)[0];
        assert!(m.has_init_guard(id("a")));
        assert!(m.has_init_guard(id("b")));
        assert!(!m.has_init_guard(id("c")));
        assert!(m.has_init_guard(id("d")));
    }

    #[test]
    fn auth_status_tracks_branches_and_helper_bodies() {
        let p = project(
            r#"
            fn require_admin(e: &Env) {}
            fn require_owner(e: &Env) { let o: Address = e.storage().instance().get(&K::Owner).unwrap(); o.require_auth(); }
            #[contractimpl]
            impl C {
                pub fn fake(e: Env) { require_admin(&e); }
                pub fn real(e: Env) { require_owner(&e); }
                pub fn external(e: Env) { require_operator_auth(&e); }
                pub fn half(e: Env, a: Address, f: bool) { if f { a.require_auth(); } }
                pub fn both(e: Env, a: Address, b: Address, f: bool) { if f { a.require_auth(); } else { b.require_auth(); } }
                pub fn arms(e: Env, a: Address, k: u32) { match k { 0 => a.require_auth(), _ => panic!("no") } }
                pub fn looped(e: Env, xs: Vec<Address>) { for x in xs.iter() { x.require_auth(); } }
                pub fn helper_in_branch(e: Env, f: bool) { if f { require_owner(&e); } }
                pub fn closure_iter(e: Env, xs: Vec<Address>) { xs.iter().for_each(|x| x.require_auth()); }
                pub fn closure_unused(e: Env, a: Address) { let _f = || a.require_auth(); }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let st = |n: &str| m.auth_status(m.by_name(n)[0]);
        assert_eq!(st("fake"), AuthStatus::Never);
        assert_eq!(st("real"), AuthStatus::Always);
        assert_eq!(st("external"), AuthStatus::Always, "undefined auth-named helpers are trusted");
        assert_eq!(st("half"), AuthStatus::Sometimes);
        assert_eq!(st("both"), AuthStatus::Always);
        assert_eq!(st("arms"), AuthStatus::Always);
        assert_eq!(st("looped"), AuthStatus::Sometimes);
        assert_eq!(st("helper_in_branch"), AuthStatus::Sometimes);
        assert_eq!(st("closure_iter"), AuthStatus::Sometimes);
        assert_eq!(st("closure_unused"), AuthStatus::Sometimes);
    }

    #[test]
    fn resolves_calls_by_module_and_type() {
        let p = project(
            r#"
            mod a { pub fn guard(e: &Env) { let x: Address = e.storage().instance().get(&1u32).unwrap(); x.require_auth(); } }
            mod b { pub fn guard(e: &Env) {} }
            pub struct S;
            impl S { pub fn guard(e: &Env) { let x: Address = todo(); x.require_auth(); } }
            fn guard(e: &Env) {}
            #[contractimpl]
            impl C {
                pub fn via_b(e: Env) { b::guard(&e); }
                pub fn via_a(e: Env) { a::guard(&e); }
                pub fn via_type(e: Env) { S::guard(&e); }
                pub fn local(e: Env) { guard(&e); }
                pub fn aliased(e: Env) { other::guard(&e); }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let st = |n: &str| m.auth_status(m.by_name(n)[0]);
        assert_eq!(st("via_b"), AuthStatus::Never);
        assert_eq!(st("via_a"), AuthStatus::Always);
        assert_eq!(st("via_type"), AuthStatus::Always);
        assert_eq!(st("local"), AuthStatus::Never, "unqualified call prefers the same module");
        assert_eq!(st("aliased"), AuthStatus::Always, "unknown qualifier falls back to all candidates");
        assert_eq!(m.fns[m.by_name("guard")[0]].module, vec!["a".to_string()]);
    }

    #[test]
    fn follows_trait_impls_and_default_methods() {
        let p = project(
            r#"
            pub trait Store {
                fn put(e: &Env, v: &Address);
                fn reset(e: &Env) { e.storage().instance().remove(&K::Admin); }
            }
            pub struct S;
            impl Store for S { fn put(e: &Env, v: &Address) { e.storage().instance().set(&K::Admin, v); } }
            #[contractimpl]
            impl C {
                pub fn qualified(e: Env, n: Address) { <S as Store>::put(&e, &n); }
                pub fn by_type(e: Env, n: Address) { S::put(&e, &n); }
                pub fn default_method(e: Env) { S::reset(&e); }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        let writes = |n: &str| m.witness(m.by_name(n)[0], &|_, f| f.state_writes.first().map(|w| w.span)).is_some();
        assert!(writes("qualified"));
        assert!(writes("by_type"));
        assert!(writes("default_method"));
    }

    #[test]
    fn follows_helpers_in_local_dependency_crates() {
        let common = CrateInfo { name: Some("common".into()), ..Default::default() };
        let vault = CrateInfo { name: Some("vault".into()), local_deps: vec!["common".into()], ..Default::default() };
        let mut p = Project::from_sources(
            [(
                "common/src/lib.rs",
                "pub fn require_admin(e: &Env) {}
                 pub fn require_owner_auth(e: &Env) { let a: Address = todo(); a.require_auth(); }
                 pub fn set(e: &Env) {}",
            )],
            common,
            false,
        );
        let v = Project::from_sources(
            [(
                "vault/src/lib.rs",
                "#[contractimpl] impl V {
                    pub fn fake(e: Env) { common::require_admin(&e); }
                    pub fn real(e: Env) { require_owner_auth(&e); }
                 }
                 fn set(e: &Env) {}",
            )],
            vault.clone(),
            false,
        );
        p.files.extend(v.files.into_iter().map(|mut f| {
            f.crate_id = 1;
            f
        }));
        p.crates.push(vault);
        let models = CrateModel::build_all(&p, &ModelOptions::default());
        let m = &models[1];
        let id = |n: &str| m.by_name(n).iter().copied().find(|&i| !m.fns[i].foreign).unwrap();
        assert_eq!(m.auth_status(id("fake")), AuthStatus::Never);
        assert_eq!(m.auth_status(id("real")), AuthStatus::Always);
        assert_eq!(m.fns_in_file(0).count(), 0, "dependency functions are not reported");
        // Unqualified `set` prefers the crate's own function.
        let call = CallSite { name: "set".into(), ..m.facts[id("fake")].calls[0].clone() };
        let call = CallSite { qualifier: None, ..call };
        assert!(m.resolve(id("fake"), &call).iter().all(|&c| !m.fns[c].foreign));
    }

    #[test]
    fn file_module_paths() {
        use std::path::Path;
        assert!(file_module_path(Path::new("c/src/lib.rs")).is_empty());
        assert_eq!(file_module_path(Path::new("c/src/a/mod.rs")), vec!["a"]);
        assert_eq!(file_module_path(Path::new("c/src/a/b.rs")), vec!["a", "b"]);
    }

    #[test]
    fn configured_auth_functions_are_trusted() {
        let p = project("#[contractimpl] impl C { pub fn a(e: Env) { gate(&e); } }");
        let opts = ModelOptions { auth_functions: vec!["gate".into()] };
        let m = CrateModel::build(&p, 0, &opts);
        assert_eq!(m.auth_status(0), AuthStatus::Always);
    }

    #[test]
    fn auth_helper_names() {
        assert!(is_auth_helper_name("require_admin_auth", &[]));
        assert!(is_auth_helper_name("enforce_owner_auth", &[]));
        assert!(is_auth_helper_name("ensure_role", &[]));
        assert!(!is_auth_helper_name("transfer", &[]));
        assert!(!is_auth_helper_name("__check_auth", &[]));
        assert!(is_auth_helper_name("gate", &["gate".into()]));
    }

    #[test]
    fn outflows_detected_through_bindings() {
        let p = project(
            r#"
            #[contractimpl]
            impl C {
                pub fn w(e: Env, to: Address, amt: i128) {
                    let me = e.current_contract_address();
                    token::Client::new(&e, &t).transfer(&me, &to, &amt);
                }
                pub fn d(e: Env, from: Address, amt: i128) {
                    token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amt);
                }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        assert_eq!(m.facts[m.by_name("w")[0]].outflows.len(), 1);
        assert_eq!(m.facts[m.by_name("d")[0]].outflows.len(), 0);
    }

    #[test]
    fn raw_invoke_contract_transfers_are_outflows() {
        let p = project(
            r#"
            #[contractimpl]
            impl C {
                pub fn a(e: Env, t: Address, to: Address, amt: i128) {
                    let args = vec![&e, e.current_contract_address().into_val(&e), to.into_val(&e), amt.into_val(&e)];
                    e.invoke_contract::<()>(&t, &Symbol::new(&e, "transfer"), args);
                }
                pub fn b(e: Env, t: Address, to: Address, amt: i128) {
                    let me = e.current_contract_address();
                    let _ = e.try_invoke_contract::<(), Error>(&t, &symbol_short!("transfer"), (me, to, amt).into_val(&e));
                }
                pub fn deposit(e: Env, t: Address, from: Address, amt: i128) {
                    let args = vec![&e, from.into_val(&e), e.current_contract_address().into_val(&e), amt.into_val(&e)];
                    e.invoke_contract::<()>(&t, &Symbol::new(&e, "transfer"), args);
                }
                pub fn other(e: Env, t: Address) {
                    let args = vec![&e, e.current_contract_address().into_val(&e)];
                    e.invoke_contract::<i128>(&t, &Symbol::new(&e, "balance"), args);
                }
            }
        "#,
        );
        let m = CrateModel::build(&p, 0, &ModelOptions::default());
        assert_eq!(m.facts[m.by_name("a")[0]].outflows.len(), 1);
        assert_eq!(m.facts[m.by_name("b")[0]].outflows.len(), 1);
        assert_eq!(m.facts[m.by_name("deposit")[0]].outflows.len(), 0);
        assert_eq!(m.facts[m.by_name("other")[0]].outflows.len(), 0);
    }
}
