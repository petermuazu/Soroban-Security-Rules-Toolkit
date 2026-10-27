//! SG-001: exported contract functions that change state, move funds or
//! upgrade the contract without any authorization check.

use guard_engine::{Confidence, Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, Severity};
use guard_parser::{AuthStatus, FnFacts, Span, Witness};

use crate::sg005_unprotected_init::is_initializer_name;
use crate::util::{has_word, word_set};

pub struct MissingAuthorization;

static META: RuleMeta = RuleMeta {
    id: "SG-001",
    name: "missing-authorization",
    summary: "Potential missing authorization check",
    description: "An exported contract function writes to storage, transfers tokens out of the contract, or \
upgrades the contract WASM, but neither it nor any helper it calls invokes `require_auth()` / \
`require_auth_for_args()` (or a recognised access-control helper or attribute). Anyone can call such a \
function with arbitrary arguments.",
    remediation: "Review whether this operation requires `address.require_auth()` (on the affected user or the stored \
admin). If the function is intentionally permissionless, add `// stellar-guard-ignore SG-001 -- <reason>`.",
    default_severity: Severity::Warning,
    tags: &["security", "authorization", "access-control"],
    options: &[
        RuleOption {
            name: "ignore-functions",
            description: "Exported function names that are intentionally permissionless.",
            default: "[]",
        },
        RuleOption {
            name: "privileged-keys",
            description: "Extra storage-key words treated as privileged (in addition to admin, owner, …).",
            default: "[]",
        },
    ],
};

/// Storage-key words that indicate privileged configuration.
pub(crate) const PRIVILEGED_WORDS: &[&str] = &[
    "admin",
    "administrator",
    "owner",
    "operator",
    "minter",
    "manager",
    "governance",
    "governor",
    "upgrader",
    "pauser",
    "guardian",
    "authority",
    "treasury",
    "signer",
    "signers",
    "wasm",
];

/// Functions with protocol-defined semantics.
const SKIPPED: &[&str] = &["__constructor", "__check_auth"];

#[derive(Clone, Copy)]
enum Sensitive {
    Upgrade,
    Outflow,
    PrivilegedWrite,
    Write,
}

impl Rule for MissingAuthorization {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>) {
        let ignored = cx.options.string_list("ignore-functions");
        let privileged = word_set(PRIVILEGED_WORDS, cx.options.string_list("privileged-keys"));
        let model = cx.model;

        for (id, f) in model.fns_in_file(cx.file_idx) {
            if !f.is_contract_export()
                || SKIPPED.contains(&f.name.as_str())
                || ignored.contains(&f.name)
                || is_initializer_name(&f.name, &[])
            {
                continue;
            }
            let auth = model.auth_status(id);
            if auth != AuthStatus::Never {
                if let Some(d) = wrong_subject(model, id, f) {
                    out.push(d);
                } else if let Some(d) = self_authorized(model, id, f, &privileged) {
                    out.push(d);
                }
                out.extend(narrow_auth_args(model, id, f));
            }
            if auth == AuthStatus::Always {
                continue;
            }

            let privileged_write = |_: &guard_parser::FnDef<'_>, facts: &FnFacts| -> Option<Span> {
                facts
                    .state_writes
                    .iter()
                    .find(|w| w.key_idents.last().is_some_and(|i| has_word(i, &privileged)))
                    .map(|w| w.span)
            };
            let found: Option<(Sensitive, Witness)> = model
                .witness(id, &|_, facts| facts.upgrades.first().copied())
                .map(|w| (Sensitive::Upgrade, w))
                .or_else(|| {
                    model.witness(id, &|_, facts| facts.outflows.first().copied()).map(|w| (Sensitive::Outflow, w))
                })
                .or_else(|| model.witness(id, &privileged_write).map(|w| (Sensitive::PrivilegedWrite, w)))
                .or_else(|| {
                    model
                        .witness(id, &|_, facts| facts.state_writes.first().map(|w| w.span))
                        .map(|w| (Sensitive::Write, w))
                });
            let Some((kind, witness)) = found else { continue };

            let (what, mut confidence) = match kind {
                Sensitive::Upgrade => ("upgrades the contract WASM", Confidence::High),
                Sensitive::Outflow => ("transfers tokens out of the contract", Confidence::High),
                Sensitive::PrivilegedWrite => ("modifies privileged configuration", Confidence::High),
                Sensitive::Write if f.takes_address() => ("writes contract storage", Confidence::Medium),
                Sensitive::Write => ("writes contract storage", Confidence::Low),
            };
            let partial = auth == AuthStatus::Sometimes;
            // A plain write is far more suspicious when the function's own comment says it is
            // admin-only, or when the contract's other setters all check authorization.
            let mut context = String::new();
            if matches!(kind, Sensitive::Write) && !partial {
                if documents_auth(&cx.file.text, f.name_span.start.line) {
                    confidence = Confidence::High;
                    context = "; its comment says it requires authorization".into();
                } else if !f.takes_address() {
                    let guarded = guarded_siblings(model, id, f);
                    if guarded >= 2 {
                        // Some contracts mix admin setters with deliberately public updates
                        // (`gulp`, `update_status`), so this alone is not high confidence.
                        confidence = Confidence::Medium;
                        let ty = f.self_ty.as_deref().unwrap_or("the contract");
                        context =
                            format!(", unlike {guarded} other state-changing functions of `{ty}` that require it");
                    }
                }
            }
            let mut witness = witness;
            let mut what = what;
            if partial {
                // A plain write behind conditional auth is usually a deliberate "authorize only
                // when needed" pattern, unless it decreases a value keyed by a parameter (a
                // balance debit that runs on the paths without auth).
                if matches!(kind, Sensitive::Write) {
                    let Some(debit) = model.debits(id).into_iter().next() else { continue };
                    witness = Witness { span: debit.span, via: vec![] };
                    what = "decreases a stored balance";
                }
                confidence = Confidence::Medium;
            }
            let via = if witness.via.is_empty() {
                String::new()
            } else {
                format!(" (via `{}`)", witness.via.join("` → `"))
            };
            let message = if partial {
                format!(
                    "Exported function `{}` {what}{via}, but authorizes only on some code paths (inside a branch, loop or closure)",
                    f.name
                )
            } else {
                format!("Exported function `{}` {what}{via} without an authorization check{context}", f.name)
            };
            let mut d = Diagnostic::new(witness.span, message, confidence).in_function(&f.name);
            if confidence == Confidence::Low {
                // A plain storage write with no address involved (e.g. a public counter) is
                // often intentional; report it without failing CI by default.
                d = d.with_severity(Severity::Info);
            }
            out.push(d);
        }
    }
}

/// Comment phrases stating that a function is restricted to a privileged caller.
const AUTH_PHRASES: &[&str] = &[
    "requires admin",
    "require admin",
    "admin authorization",
    "admin auth",
    "admin only",
    "admin-only",
    "only admin",
    "only the admin",
    "only owner",
    "only the owner",
    "owner only",
    "owner-only",
    "requires owner",
    "must be called by the admin",
    "must be called by the owner",
    "callable only by",
    "can only be called by",
];

/// `true` if the comments directly above the function on line `fn_line`
/// (`//` or `///`, skipping attributes) say it requires a privileged caller.
fn documents_auth(text: &str, fn_line: usize) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let mut comment = String::new();
    let mut i = fn_line.saturating_sub(1);
    while i > 0 {
        i -= 1;
        let l = lines.get(i).map(|l| l.trim()).unwrap_or("");
        if l.starts_with("#[") || l.is_empty() && comment.is_empty() {
            continue;
        }
        let Some(c) = l.strip_prefix("//") else { break };
        comment.push(' ');
        comment.push_str(&c.trim_start_matches(['/', '!']).to_lowercase());
    }
    AUTH_PHRASES.iter().any(|p| comment.contains(p))
}

/// Number of other exported functions of the same contract type that write
/// state, take no address and always authorize: admin-style setters.
fn guarded_siblings(model: &guard_parser::CrateModel<'_>, id: usize, f: &guard_parser::FnDef<'_>) -> usize {
    let Some(ty) = &f.self_ty else { return 0 };
    model
        .fns
        .iter()
        .enumerate()
        .filter(|&(other, g)| {
            other != id
                && g.is_contract_export()
                && g.self_ty.as_ref() == Some(ty)
                && !g.takes_address()
                && model.auth_status(other) == AuthStatus::Always
                && model.witness(other, &|_, facts| facts.state_writes.first().map(|w| w.span)).is_some()
        })
        .count()
}

/// Reports a balance debit keyed by an address parameter that never authorizes,
/// when every authorization in the function is on *other* caller-chosen addresses
/// (`caller.require_auth(); spend_balance(&e, &victim, amount)`).
///
/// Not reported when some authorization targets a stored admin or an opaque
/// helper (admin clawback), or when another debit is keyed by both the debited
/// and an authorized address (allowance spending in `transfer_from`).
fn wrong_subject(model: &guard_parser::CrateModel<'_>, id: usize, f: &guard_parser::FnDef<'_>) -> Option<Diagnostic> {
    let auth = model.subject_auth(id);
    if auth.other || auth.params.is_empty() {
        return None;
    }
    let params = f.params();
    let is_address = |i: usize| {
        params.get(i).is_some_and(|(_, ty)| guard_parser::syntax::idents(*ty).iter().any(|t| t == "Address"))
    };
    let debits = model.debits(id);
    for d in &debits {
        let Some(&victim) = d.key_params.iter().find(|&&i| is_address(i) && !auth.params.contains(&i)) else {
            continue;
        };
        if d.key_params.iter().any(|i| auth.params.contains(i)) {
            continue;
        }
        let delegated = debits
            .iter()
            .any(|o| o.key_params.contains(&victim) && o.key_params.iter().any(|i| auth.params.contains(i)));
        if delegated {
            continue;
        }
        let names: Vec<String> = auth.params.iter().map(|&i| format!("`{}`", params[i].0)).collect();
        let message = format!(
            "Exported function `{}` decreases a value keyed by `{}`, but only {} authorizes",
            f.name,
            params[victim].0,
            names.join(", ")
        );
        return Some(Diagnostic::new(d.span, message, Confidence::Medium).in_function(&f.name).with_help(format!(
            "Call `{}.require_auth()` before debiting it, or check an allowance granted by `{}` to the caller.",
            params[victim].0, params[victim].0
        )));
    }
    None
}

/// Reports an upgrade or privileged write whose only authorization is `require_auth()`
/// on caller-supplied address parameters that are never checked against anything
/// (`caller.require_auth(); set(&DataKey::Admin, &new_admin)`). Anyone can pass and
/// sign for their own address, so the check proves nothing.
///
/// Conservative: any other use of the authorized parameter (a comparison, a role-check
/// helper call, a storage key, an `assert!`) counts as a check, and a write keyed by
/// the authorized parameter (per-user data the caller owns) is not reported.
fn self_authorized(
    model: &guard_parser::CrateModel<'_>,
    id: usize,
    f: &guard_parser::FnDef<'_>,
    privileged: &[String],
) -> Option<Diagnostic> {
    let auth = model.subject_auth(id);
    if auth.other || auth.params.is_empty() {
        return None;
    }
    let params = f.params();
    let names: Vec<String> = auth.params.iter().filter_map(|&i| params.get(i).map(|(n, _)| n.clone())).collect();
    if names.len() != auth.params.len() || names.iter().any(|n| uses_besides_auth(f.block, n) > 0) {
        return None;
    }
    let lowered: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let (what, witness) = model
        .witness(id, &|_, facts| facts.upgrades.first().copied())
        .map(|w| ("upgrades the contract WASM", w))
        .or_else(|| {
            model
                .witness(id, &|_, facts| {
                    facts
                        .state_writes
                        .iter()
                        .find(|w| {
                            w.key_idents.last().is_some_and(|i| has_word(i, privileged))
                                && !w.key_locals.iter().any(|l| lowered.contains(l))
                        })
                        .map(|w| w.span)
                })
                .map(|w| ("modifies privileged configuration", w))
        })?;
    let via = if witness.via.is_empty() { String::new() } else { format!(" (via `{}`)", witness.via.join("` → `")) };
    let shown: Vec<String> = names.iter().map(|n| format!("`{n}`")).collect();
    let message = format!(
        "Exported function `{}` {what}{via}, but its only authorization is `require_auth()` on caller-supplied {}, \
which is never checked against a stored admin or role",
        f.name,
        shown.join(", ")
    );
    Some(Diagnostic::new(witness.span, message, Confidence::High).in_function(&f.name).with_help(format!(
        "Anyone can pass their own address as {} and sign for it. Load the stored admin and call \
`admin.require_auth()`, or compare {} with it before the change.",
        shown.join(", "),
        shown.join(", ")
    )))
}

/// Number of uses of the parameter `name` in `block`, other than as the receiver of
/// `require_auth()` / `require_auth_for_args(..)` or inside an event publication.
/// Uses inside macros (`assert_eq!(caller, admin)`) count.
fn uses_besides_auth(block: &syn::Block, name: &str) -> usize {
    use syn::visit::Visit;
    struct Uses<'n> {
        name: &'n str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Uses<'_> {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            let method = m.method.to_string();
            if method.starts_with("require_auth") && is_path_named(&m.receiver, self.name) {
                for arg in &m.args {
                    self.visit_expr(arg);
                }
                return;
            }
            if method == "publish" && receiver_chain_has(&m.receiver, "events") {
                return;
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_path(&mut self, p: &'ast syn::Path) {
            if p.is_ident(self.name) {
                self.count += 1;
            }
            syn::visit::visit_path(self, p);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let text = mac.tokens.to_string();
            self.count += text.split(|c: char| !(c.is_alphanumeric() || c == '_')).filter(|w| *w == self.name).count();
        }
    }
    let mut v = Uses { name, count: 0 };
    v.visit_block(block);
    v.count
}

fn is_path_named(expr: &syn::Expr, name: &str) -> bool {
    match expr {
        syn::Expr::Path(p) => p.path.is_ident(name),
        syn::Expr::Reference(r) => is_path_named(&r.expr, name),
        syn::Expr::Paren(p) => is_path_named(&p.expr, name),
        syn::Expr::MethodCall(m) if m.method == "clone" => is_path_named(&m.receiver, name),
        _ => false,
    }
}

fn receiver_chain_has(expr: &syn::Expr, method: &str) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => m.method == method || receiver_chain_has(&m.receiver, method),
        _ => false,
    }
}

/// Reports `require_auth_for_args(..)` calls whose argument list includes none of
/// the parameters that control a sensitive operation: `i128`/`u128` amounts and
/// `Address`es (other than the authorizing one). The signature can then be reused
/// with any amount and recipient.
fn narrow_auth_args(model: &guard_parser::CrateModel<'_>, id: usize, f: &guard_parser::FnDef<'_>) -> Vec<Diagnostic> {
    let facts = &model.facts[id];
    if facts.auth_for_args.is_empty() {
        return vec![];
    }
    let sensitive = model.witness(id, &|_, x| x.outflows.first().or(x.state_writes.first().map(|w| &w.span)).copied());
    if sensitive.is_none() {
        return vec![];
    }
    let mut out = Vec::new();
    for (span, subject, args) in &facts.auth_for_args {
        let relevant: Vec<String> = f
            .params()
            .into_iter()
            .filter(|(name, ty)| {
                let t = guard_parser::syntax::compact(*ty);
                matches!(t.trim_start_matches('&'), "i128" | "u128" | "Address") && Some(name) != subject.as_ref()
            })
            .map(|(n, _)| n)
            .collect();
        // Signing a deliberate subset (as in an atomic swap, where each party signs its own
        // side) is a design choice; only an argument list that covers none of them is reported.
        if relevant.is_empty() || relevant.iter().any(|n| args.contains(n)) {
            continue;
        }
        let missing: Vec<String> = relevant.iter().map(|n| format!("`{n}`")).collect();
        let message = format!(
            "Exported function `{}` calls `require_auth_for_args` without {} in the signed arguments",
            f.name,
            missing.join(", ")
        );
        out.push(Diagnostic::new(*span, message, Confidence::Medium).in_function(&f.name).with_help(
            "Include every amount and address that the call acts on in the `require_auth_for_args` \
arguments, or use `require_auth()` so the full invocation is signed.",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use guard_engine::Settings;

    fn check(src: &str) -> Vec<guard_engine::Finding> {
        run(Box::new(MissingAuthorization), src)
    }

    #[test]
    fn documented_admin_only_setter_without_auth_is_high_confidence() {
        let f = check(
            r#"
fn set_costs(e: &Env, c: &Vec<u64>) { e.storage().instance().set(&COST_KEY, c); }
#[contractimpl]
impl Oracle {
    // Update costs configuration
    // Requires admin authorization
    pub fn set_costs_config(e: &Env, config: Vec<u64>) {
        set_costs(e, &config);
    }
    /// Public counter.
    pub fn bump(e: &Env) { e.storage().instance().set(&COUNT, &1u32); }
}
"#,
        );
        assert_eq!(f.len(), 2, "{f:#?}");
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("comment says"));
        assert_eq!(f[1].severity, Severity::Info, "plain public write stays info");
    }

    #[test]
    fn setter_without_the_auth_its_siblings_have_is_a_warning() {
        let f = check(
            r#"
fn admin_check(e: &Env) { let a: Address = e.storage().instance().get(&ADMIN).unwrap(); a.require_auth(); }
#[contractimpl]
impl Oracle {
    pub fn set_cache_size(e: &Env, n: u32) { admin_check(e); e.storage().instance().set(&CACHE, &n); }
    pub fn set_period(e: &Env, p: u64) { admin_check(e); e.storage().instance().set(&PERIOD, &p); }
    pub fn set_costs(e: &Env, c: Vec<u64>) { e.storage().instance().set(&COSTS, &c); }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].confidence, Confidence::Medium);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("unlike 2 other"), "{}", f[0].message);
    }

    // ---- true positives -------------------------------------------------

    const LEDGER: &str = r#"
fn bal(e: &Env, a: &Address) -> i128 { e.storage().persistent().get(&K::Bal(a.clone())).unwrap_or(0) }
fn put(e: &Env, a: &Address, v: i128) { e.storage().persistent().set(&K::Bal(a.clone()), &v); }
fn spend(e: &Env, a: Address, amount: i128) { let b = bal(e, &a); if b < amount { panic!() } put(e, &a, b - amount); }
fn spend_allowance(e: &Env, from: Address, spender: Address, amount: i128) {
    let cur: i128 = e.storage().temporary().get(&K::Allow(from.clone(), spender.clone())).unwrap_or(0);
    let v = Allowance { amount: cur - amount };
    e.storage().temporary().set(&K::Allow(from, spender), &v);
}
"#;

    #[test]
    fn resolves_constant_keys() {
        let f = check(
            r#"
const KEY: Symbol = symbol_short!("ADMIN");
mod keys { pub const SLOT: Symbol = symbol_short!("OWNER"); }
#[contractimpl]
impl C {
    pub fn set_a(e: Env, a: Address) { e.storage().instance().set(&KEY, &a); }
    pub fn set_b(e: Env, a: Address) { e.storage().instance().set(&keys::SLOT, &a); }
}
"#,
        );
        assert_eq!(f.len(), 2, "{f:#?}");
        assert!(f.iter().all(|x| x.message.contains("privileged configuration")), "{f:#?}");
    }

    #[test]
    fn flags_debit_behind_conditional_auth() {
        let src = format!(
            "{LEDGER}#[contractimpl] impl T {{
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {{
        if amount > 0 {{ from.require_auth(); }}
        spend(&e, from, amount);
    }}
    pub fn touch(e: Env, who: Address, f: bool) {{
        if f {{ who.require_auth(); }}
        put(&e, &who, 1);
    }}
}}"
        );
        let f = check(&src);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(
            f[0].message.contains("`transfer` decreases a stored balance, but authorizes only on some"),
            "{}",
            f[0].message
        );
    }

    #[test]
    fn flags_narrow_require_auth_for_args() {
        let f = check(
            r#"
#[contractimpl]
impl V {
    pub fn withdraw(e: Env, user: Address, to: Address, amount: i128) {
        user.require_auth_for_args(vec![&e]);
        token::Client::new(&e, &t).transfer(&e.current_contract_address(), &to, &amount);
    }
    pub fn withdraw_ok(e: Env, user: Address, to: Address, amount: i128) {
        user.require_auth_for_args((to.clone(), amount).into_val(&e));
        token::Client::new(&e, &t).transfer(&e.current_contract_address(), &to, &amount);
    }
    pub fn swap_side(e: Env, a: Address, b: Address, amount_a: i128, amount_b: i128) {
        a.require_auth_for_args((amount_a,).into_val(&e));
        token::Client::new(&e, &t).transfer(&e.current_contract_address(), &to, &amount);
    }
    pub fn note(e: Env, user: Address, amount: i128) {
        user.require_auth_for_args(vec![&e]);
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("without `to`, `amount`"), "{}", f[0].message);
        assert_eq!(f[0].function.as_deref(), Some("withdraw"));
    }

    #[test]
    fn flags_debit_of_unauthorized_address() {
        let src = format!(
            "{LEDGER}#[contractimpl] impl T {{
    pub fn steal(e: Env, caller: Address, victim: Address, amount: i128) {{
        caller.require_auth();
        spend(&e, victim, amount);
    }}
}}"
        );
        let f = check(&src);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("keyed by `victim`, but only `caller` authorizes"), "{}", f[0].message);
        assert_eq!(f[0].confidence, Confidence::Medium);
    }

    #[test]
    fn debit_patterns_that_are_authorized() {
        let src = format!(
            "{LEDGER}#[contractimpl] impl T {{
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {{
        from.require_auth();
        spend(&e, from.clone(), amount);
        put(&e, &to, bal(&e, &to).checked_add(amount).unwrap());
    }}
    pub fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) {{
        spender.require_auth();
        spend_allowance(&e, from.clone(), spender, amount);
        spend(&e, from, amount);
    }}
    pub fn clawback(e: Env, from: Address, amount: i128) {{
        let admin: Address = e.storage().instance().get(&K::Admin).unwrap();
        admin.require_auth();
        spend(&e, from, amount);
    }}
}}"
        );
        let f = check(&src);
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn flags_withdraw_without_auth() {
        let f = check(
            r#"
#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let client = token::Client::new(&env, &read_token(&env));
        client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![6]);
        assert_eq!(f[0].confidence, Confidence::High);
        assert!(f[0].message.contains("transfers tokens out"), "{}", f[0].message);
        assert_eq!(f[0].function.as_deref(), Some("withdraw"));
    }

    #[test]
    fn flags_set_admin_and_upgrade() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }
    pub fn upgrade(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(hash);
    }
    pub fn upgrade2(env: Env, hash: BytesN<32>) {
        env.deployer().update_current_contract(ContractExecutable::Wasm(hash));
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![5, 8, 11]);
        assert!(f.iter().all(|x| x.confidence == Confidence::High));
    }

    #[test]
    fn flags_write_through_helper_and_reports_call_site() {
        let f = check(
            r#"
fn write_balance(e: &Env, who: &Address, v: i128) {
    e.storage().persistent().set(&DataKey::Balance(who.clone()), &v);
}
#[contractimpl]
impl Token {
    pub fn mint(e: Env, to: Address, amount: i128) {
        write_balance(&e, &to, amount);
    }
}
"#,
        );
        assert_eq!(lines(&f), vec![8]);
        assert_eq!(f[0].confidence, Confidence::Medium);
        assert!(f[0].message.contains("via `write_balance`"));
    }

    #[test]
    fn trait_impl_functions_are_exported() {
        let f = check(
            r#"
#[contractimpl]
impl TokenInterface for Token {
    fn burn(e: Env, from: Address, amount: i128) {
        e.storage().persistent().remove(&DataKey::Balance(from));
    }
}
"#,
        );
        assert_eq!(f.len(), 1);
    }

    // ---- false positives that must NOT be reported ----------------------

    #[test]
    fn direct_and_helper_auth_are_recognised() {
        let f = check(
            r#"
fn require_admin(e: &Env) {
    let admin: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}
#[contractimpl]
impl C {
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        e.storage().persistent().set(&DataKey::Balance(to), &amount);
    }
    pub fn set_admin(e: Env, a: Address) {
        require_admin(&e);
        e.storage().instance().set(&DataKey::Admin, &a);
    }
    pub fn vote(e: Env, voter: Address, args: Vec<Val>) {
        voter.require_auth_for_args(args);
        e.storage().persistent().set(&DataKey::Vote(voter), &true);
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn read_only_ttl_and_internal_fns_are_ignored() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn balance(e: Env, id: Address) -> i128 {
        e.storage().persistent().get(&DataKey::Balance(id)).unwrap_or(0)
    }
    pub fn bump(e: Env) {
        e.storage().instance().extend_ttl(100, 200);
    }
    fn internal(e: Env) {
        e.storage().instance().set(&DataKey::X, &1);
    }
    pub fn __constructor(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }
}
impl NotAContract {
    pub fn set(e: Env) { e.storage().instance().set(&DataKey::X, &1); }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn deposit_from_user_is_not_an_outflow() {
        let f = check(
            r#"
#[contractimpl]
impl Vault {
    pub fn deposit(e: Env, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&e, &t).transfer(&from, &e.current_contract_address(), &amount);
    }
}
"#,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn access_control_attributes_and_custom_helpers() {
        let src = r#"
#[contractimpl]
impl C {
    #[only_owner]
    pub fn pause(e: Env) { e.storage().instance().set(&DataKey::Paused, &true); }
    pub fn unpause(e: Env) { gate(&e); e.storage().instance().set(&DataKey::Paused, &false); }
}
"#;
        let f = check(src);
        assert_eq!(f.len(), 1, "only `unpause` without configured helper");
        assert_eq!((f[0].confidence, f[0].severity), (Confidence::Low, Severity::Info));
        let settings = Settings { auth_functions: vec!["gate".into()], ..Default::default() };
        let f = run_with(Box::new(MissingAuthorization), src, soroban_crate(Some(true)), &settings);
        assert!(f.is_empty());
    }

    #[test]
    fn privileged_keys_use_the_variant_name() {
        let f = check(
            r#"
#[contractimpl]
impl Gov {
    pub fn queue(e: Env, id: u32, op: BytesN<32>) {
        e.storage().persistent().set(&GovernorKey::OperationId(id), &op);
    }
}
"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, Confidence::Low, "not a privileged write: {}", f[0].message);
    }

    #[test]
    fn ignore_functions_option() {
        let mut settings = Settings::default();
        settings
            .rule_mut("SG-001")
            .options
            .insert("ignore-functions".into(), toml::Value::Array(vec![toml::Value::String("increment".into())]));
        let f = run_with(
            Box::new(MissingAuthorization),
            "#[contractimpl] impl C { pub fn increment(e: Env) { e.storage().instance().set(&K::C, &1); } }",
            soroban_crate(Some(true)),
            &settings,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn initializers_are_left_to_sg005() {
        let f = check(
            "#[contractimpl] impl C { pub fn initialize(e: Env, a: Address) { e.storage().instance().set(&K::Admin, &a); } }",
        );
        assert!(f.is_empty());
    }

    // ---- self-authorization: `caller.require_auth()` with an unchecked caller ----

    #[test]
    fn flags_admin_write_authorized_only_by_unchecked_caller() {
        let f = check(
            r#"
#[contractimpl]
impl C {
    pub fn set_admin(e: Env, caller: Address, new_admin: Address) {
        caller.require_auth();
        e.storage().instance().set(&DataKey::Admin, &new_admin);
        e.events().publish((symbol_short!("admin"), caller), new_admin);
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].confidence, Confidence::High);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("caller-supplied `caller`"), "{}", f[0].message);
    }

    #[test]
    fn flags_upgrade_authorized_only_by_unchecked_caller_via_helper_write() {
        let f = check(
            r#"
fn do_upgrade(e: &Env, h: BytesN<32>) { e.deployer().update_current_contract_wasm(h); }
#[contractimpl]
impl C {
    pub fn upgrade(e: Env, operator: Address, hash: BytesN<32>) {
        operator.require_auth();
        do_upgrade(&e, hash);
    }
}
"#,
        );
        assert_eq!(f.len(), 1, "{f:#?}");
        assert!(f[0].message.contains("upgrades the contract WASM (via `do_upgrade`)"), "{}", f[0].message);
    }

    #[test]
    fn caller_checked_against_stored_admin_is_not_reported() {
        let f = check(
            r#"
fn admin(e: &Env) -> Address { e.storage().instance().get(&DataKey::Admin).unwrap() }
fn ensure_role(e: &Env, who: &Address) { if !e.storage().persistent().has(&DataKey::Role(who.clone())) { panic!() } }
#[contractimpl]
impl C {
    pub fn set_a(e: Env, caller: Address, a: Address) {
        caller.require_auth();
        if caller != admin(&e) { panic!("not admin") }
        e.storage().instance().set(&DataKey::Admin, &a);
    }
    pub fn set_b(e: Env, caller: Address, a: Address) {
        caller.require_auth();
        assert_eq!(caller, admin(&e));
        e.storage().instance().set(&DataKey::Admin, &a);
    }
    pub fn set_c(e: Env, caller: Address, a: Address) {
        caller.require_auth();
        ensure_role(&e, &caller);
        e.storage().instance().set(&DataKey::Owner, &a);
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }

    #[test]
    fn self_keyed_privileged_write_and_stored_admin_auth_are_not_reported() {
        let f = check(
            r#"
fn admin(e: &Env) -> Address { e.storage().instance().get(&DataKey::Admin).unwrap() }
#[contractimpl]
impl C {
    // Each operator registers its own settings.
    pub fn set_operator_fee(e: Env, operator: Address, fee: u32) {
        operator.require_auth();
        e.storage().persistent().set(&DataKey::Operator(operator), &fee);
    }
    pub fn set_admin(e: Env, a: Address) {
        admin(&e).require_auth();
        e.storage().instance().set(&DataKey::Admin, &a);
    }
}
"#,
        );
        assert!(f.is_empty(), "{f:#?}");
    }
}
