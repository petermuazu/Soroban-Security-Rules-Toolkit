//! Per-function fact collection: one pass over a function body.

use super::*;

/// `true` if an expression always leaves the function: `panic!`, `return`, a
/// `panic_with_error!` call, or a block ending in one of those.
pub(super) fn diverges(expr: &Expr) -> bool {
    match crate::syntax::strip(expr) {
        Expr::Return(_) => true,
        Expr::Macro(m) => {
            let n = macro_name(&m.mac);
            matches!(n.as_str(), "panic" | "panic_with_error" | "unreachable" | "unimplemented" | "todo")
        }
        Expr::Block(b) => b.block.stmts.last().is_some_and(|s| match s {
            syn::Stmt::Expr(e, _) => diverges(e),
            syn::Stmt::Macro(m) => {
                let n = macro_name(&m.mac);
                matches!(n.as_str(), "panic" | "panic_with_error" | "unreachable" | "unimplemented" | "todo")
            }
            _ => false,
        }),
        _ => false,
    }
}

/// The local passed as an argument, ignoring `&`, `*`, `.clone()`, `.into()` and the like.
pub(super) fn plain_local(e: &Expr) -> Option<String> {
    match crate::syntax::strip(e) {
        Expr::MethodCall(m)
            if m.args.is_empty() && matches!(m.method.to_string().as_str(), "clone" | "into" | "to_owned") =>
        {
            plain_local(&m.receiver)
        }
        other => crate::syntax::as_local_ident(other),
    }
}

/// Lowercase locals mentioned in an expression, following local bindings
/// (`let key = DataKey::Balance(user.clone())`).
pub(super) fn locals_in(key: &Expr, b: &Bindings<'_>) -> Vec<String> {
    let mut out: Vec<String> = resolved_idents(key, b)
        .into_iter()
        .filter(|i| i.starts_with(|c: char| c.is_lowercase()) && !matches!(i.as_str(), "clone" | "into" | "to_owned"))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `true` if the value is computed by subtraction, directly or through a local
/// (`let nb = b - amount; set(&k, &nb)`).
pub(super) fn is_decreasing(e: &Expr, b: &Bindings<'_>) -> bool {
    struct D(bool);
    impl<'ast> Visit<'ast> for D {
        fn visit_expr_binary(&mut self, x: &'ast syn::ExprBinary) {
            if matches!(x.op, syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_)) {
                self.0 = true;
            }
            syn::visit::visit_expr_binary(self, x);
        }
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if matches!(m.method.to_string().as_str(), "checked_sub" | "saturating_sub" | "wrapping_sub") {
                self.0 = true;
            }
            syn::visit::visit_expr_method_call(self, m);
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut d = D(false);
    d.visit_expr(e);
    if !d.0 {
        if let Some(init) = b.resolve(e) {
            if !std::ptr::eq(crate::syntax::strip(init), crate::syntax::strip(e)) {
                d.visit_expr(init);
            }
        }
    }
    d.0
}

/// The path segment before the function name in a call: `a::f` → `a`,
/// `<T as Trait>::f` → `Trait`.
pub(super) fn call_qualifier(c: &syn::ExprCall) -> Option<String> {
    let Expr::Path(p) = crate::syntax::strip(&c.func) else { return None };
    if let Some(q) = &p.qself {
        if q.position > 0 {
            return p.path.segments.iter().nth(q.position - 1).map(|s| s.ident.to_string());
        }
        return match &*q.ty {
            syn::Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
            _ => None,
        };
    }
    let n = p.path.segments.len();
    (n >= 2).then(|| p.path.segments[n - 2].ident.to_string())
}

pub(super) fn collect_facts(def: &FnDef<'_>, opts: &ModelOptions, consts: &HashMap<String, Vec<String>>) -> FnFacts {
    let bindings = Bindings::collect(def.block);
    let mut v = FactsVisitor {
        bindings: &bindings,
        consts,
        opts,
        facts: FnFacts { auth_attr: def.attrs.iter().any(is_auth_attr), ..Default::default() },
        cond_depth: 0,
        branch_depth: 0,
        loop_keys: HashMap::new(),
    };
    v.visit_block(def.block);
    v.facts
}

struct FactsVisitor<'b, 'a> {
    bindings: &'b Bindings<'a>,
    consts: &'b HashMap<String, Vec<String>>,
    opts: &'b ModelOptions,
    facts: FnFacts,
    cond_depth: usize,
    /// > 0 inside code that runs on some paths only.
    branch_depth: usize,
    /// Loop variables over a fixed list of keys: `for key in [K::A, K::B] { .. }`.
    loop_keys: HashMap<String, Vec<String>>,
}

impl FactsVisitor<'_, '_> {
    fn condition<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.cond_depth += 1;
        f(self);
        self.cond_depth -= 1;
    }

    fn branch<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.branch_depth += 1;
        f(self);
        self.branch_depth -= 1;
    }

    /// Records a direct authorization check, conditional or not.
    fn push_auth(&mut self, span: Span) {
        if self.branch_depth > 0 {
            self.facts.cond_auth.push(span);
        } else {
            self.facts.auth.push(span);
        }
    }

    fn push_call<'e>(
        &mut self,
        name: String,
        span: Span,
        is_method: bool,
        qualifier: Option<String>,
        args: impl IntoIterator<Item = &'e Expr>,
    ) {
        let auth_named = is_auth_helper_name(&name, &[]);
        let args = args
            .into_iter()
            .map(|a| CallArg {
                local: plain_local(a),
                decreasing: is_decreasing(a, self.bindings),
                mentions: locals_in(a, self.bindings),
                key: key_id(&self.key_names(a)),
            })
            .collect();
        self.facts.calls.push(CallSite {
            name,
            span,
            is_method,
            qualifier,
            args,
            in_condition: self.cond_depth > 0,
            in_branch: self.branch_depth > 0,
            auth_named,
        });
    }

    /// When every alternative of an `if`/`else` or `match` performs a direct
    /// auth check, the check runs on every path.
    fn promote_if_exhaustive(&mut self, all_branches_auth: bool, first: Option<Span>) {
        if all_branches_auth && self.branch_depth == 0 {
            if let Some(span) = first {
                self.facts.auth.push(span);
            }
        }
    }

    fn expr_reads_storage(&self, expr: &Expr) -> bool {
        struct R<'x, 'a> {
            b: &'x Bindings<'a>,
            hit: bool,
        }
        impl<'ast> Visit<'ast> for R<'_, '_> {
            fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
                if storage_op(m, self.b).is_some_and(|op| op.kind.is_read()) {
                    self.hit = true;
                }
                syn::visit::visit_expr_method_call(self, m);
            }
        }
        let mut r = R { b: self.bindings, hit: false };
        r.visit_expr(expr);
        r.hit
    }
}

impl FactsVisitor<'_, '_> {
    /// Key names of a storage key expression, resolving crate constants.
    fn key_names(&self, k: &Expr) -> Vec<String> {
        resolve_const_key(crate::syntax::key_names(k, self.bindings), self.consts)
    }

    /// Key name of the first storage read inside `expr`.
    fn read_key_in(&self, expr: &Expr) -> Option<String> {
        struct R<'x, 'a> {
            b: &'x Bindings<'a>,
            key: Option<Vec<String>>,
            key_found: bool,
        }
        impl<'ast> Visit<'ast> for R<'_, '_> {
            fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
                if !self.key_found {
                    if let Some(op) = storage_op(m, self.b).filter(|op| op.kind.is_read()) {
                        self.key = op.key().map(|k| crate::syntax::key_names(k, self.b));
                        self.key_found = true;
                    }
                }
                syn::visit::visit_expr_method_call(self, m);
            }
        }
        let mut r = R { b: self.bindings, key: None, key_found: false };
        r.visit_expr(expr);
        r.key.and_then(|names| resolve_const_key(names, self.consts).pop())
    }
}

impl<'ast> Visit<'ast> for FactsVisitor<'_, '_> {
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let name = m.method.to_string();
        let span = Span::of(&m.method);
        match name.as_str() {
            "require_auth" | "require_auth_for_args" => {
                self.push_auth(span);
                self.facts.auth_subjects.push(plain_local(&m.receiver));
                if name == "require_auth_for_args" {
                    let mut locals: Vec<String> = m
                        .args
                        .iter()
                        .flat_map(|a| resolved_idents(a, self.bindings))
                        .filter(|i| i.starts_with(|c: char| c.is_lowercase()))
                        .collect();
                    locals.sort();
                    locals.dedup();
                    self.facts.auth_for_args.push((span, plain_local(&m.receiver), locals));
                }
            }
            "update_current_contract_wasm" | "update_current_contract" => self.facts.upgrades.push(span),
            "publish"
                if matches!(
                    crate::syntax::strip(&m.receiver),
                    Expr::MethodCall(events) if events.method == "events"
                ) =>
            {
                self.facts.event_publishes.push(span);
            }
            "extend_ttl_for_contract_instance" | "extend_ttl_for_code" => {
                self.facts.ttl_extends.push(Some(StorageTier::Instance));
                self.facts.ttl_extend_keys.push(None);
                self.facts.ttl_extend_key_locals.push(None);
            }
            "transfer" | "transfer_from" => {
                let from_contract = m
                    .args
                    .first()
                    .is_some_and(|a| resolved_idents(a, self.bindings).iter().any(|i| i == "current_contract_address"));
                if from_contract {
                    self.facts.outflows.push(span);
                }
            }
            // A raw cross-contract `transfer`: `env.invoke_contract(&token, &Symbol::new(&e, "transfer"),
            // vec![&e, e.current_contract_address().into_val(&e), to.into_val(&e), amount.into_val(&e)])`.
            "invoke_contract" | "try_invoke_contract" if m.args.len() == 3 => {
                let func = crate::syntax::compact(&m.args[1]);
                let names_transfer = func.contains("\"transfer\"")
                    || crate::syntax::key_names(&m.args[1], self.bindings).iter().any(|n| n == "transfer");
                let from_contract = first_invoke_arg(&m.args[2], self.bindings, 0).is_some_and(|a| {
                    resolved_idents(&a, self.bindings).iter().any(|i| i == "current_contract_address")
                });
                if names_transfer && from_contract {
                    self.facts.outflows.push(span);
                }
            }
            _ => {}
        }
        let op = storage_op(m, self.bindings);
        if let Some(op) = op.as_ref().filter(|op| op.kind == StorageOpKind::ExtendTtl) {
            self.facts.ttl_extends.push(op.tier);
            let local = op.key().and_then(plain_local);
            if let Some(keys) = local.as_ref().and_then(|l| self.loop_keys.get(l)).cloned() {
                // One extension per key of the list (keeps the three vectors parallel).
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        self.facts.ttl_extends.push(op.tier);
                    }
                    self.facts.ttl_extend_keys.push(Some(k));
                    self.facts.ttl_extend_key_locals.push(None);
                }
            } else {
                let key = op.key().and_then(|k| key_id(&self.key_names(k)));
                self.facts.ttl_extend_keys.push(key);
                self.facts.ttl_extend_key_locals.push(local);
            }
        }
        if let Some(op) = op {
            if op.kind.is_write() {
                let key_text = op
                    .key()
                    .map(|k| {
                        let resolved = self.bindings.resolve(k).unwrap_or(k);
                        crate::syntax::compact(crate::syntax::strip(resolved))
                    })
                    .unwrap_or_default();
                let (key_idents, key_is_parameterised) = match op.key() {
                    Some(k) => {
                        let parameterised = match crate::syntax::strip(k) {
                            Expr::Call(c) => call_takes_values(c),
                            Expr::Path(_) => self.bindings.resolve(k).is_some_and(
                                |init| matches!(crate::syntax::strip(init), Expr::Call(c) if call_takes_values(c)),
                            ),
                            _ => false,
                        };
                        (self.key_names(k), parameterised)
                    }
                    None => (vec![], false),
                };
                let key_locals = op.key().map(|k| locals_in(k, self.bindings)).unwrap_or_default();
                let value = (op.kind == StorageOpKind::Set).then(|| m.args.iter().nth(1)).flatten();
                self.facts.state_writes.push(StateWrite {
                    span,
                    kind: op.kind,
                    tier: op.tier,
                    key_idents,
                    key_is_parameterised,
                    key_text,
                    key_locals,
                    value_locals: value.map(|v| locals_in(v, self.bindings)).unwrap_or_default(),
                    value_decreasing: value.is_some_and(|v| is_decreasing(v, self.bindings)),
                });
            } else if op.kind.is_read() {
                self.facts.storage_reads.push(span);
                if op.kind == StorageOpKind::Get {
                    if let Some(k) = op.key().and_then(|k| self.key_names(k).pop()) {
                        self.facts.read_keys.push(k);
                    }
                }
                if op.kind == StorageOpKind::Has || self.cond_depth > 0 {
                    self.facts.init_guards.push(span);
                    let key = op.key().and_then(|k| self.key_names(k).pop());
                    self.facts.init_guard_keys.push(key);
                }
            }
        } else if self.opts.auth_functions.contains(&name) {
            self.push_auth(span);
        } else if !matches!(name.as_str(), "require_auth" | "require_auth_for_args") {
            self.push_call(name, span, true, None, &m.args);
        }
        syn::visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let Some(name) = call_name(c) {
            let span = Span::of(&c.func);
            if self.opts.auth_functions.contains(&name) {
                self.push_auth(span);
            } else {
                self.push_call(name, span, false, call_qualifier(c), &c.args);
            }
        }
        syn::visit::visit_expr_call(self, c);
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.condition(|s| s.visit_expr(&e.cond));
        let before = self.facts.cond_auth.len();
        self.branch(|s| s.visit_block(&e.then_branch));
        let after_then = self.facts.cond_auth.len();
        let mut all = after_then > before;
        if let Some((_, els)) = &e.else_branch {
            self.branch(|s| s.visit_expr(els));
            all &= self.facts.cond_auth.len() > after_then;
        } else {
            all = false;
        }
        let first = self.facts.cond_auth.get(before).copied();
        self.promote_if_exhaustive(all, first);
    }

    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.condition(|s| s.visit_expr(&e.expr));
        let before = self.facts.cond_auth.len();
        let mut all = !e.arms.is_empty();
        for arm in &e.arms {
            if let Some((_, g)) = &arm.guard {
                self.condition(|s| s.visit_expr(g));
            }
            let n = self.facts.cond_auth.len();
            self.branch(|s| s.visit_expr(&arm.body));
            // An arm that diverges (`panic!`, `return`) need not authorize.
            all &= self.facts.cond_auth.len() > n || diverges(&arm.body);
        }
        let first = self.facts.cond_auth.get(before).copied();
        self.promote_if_exhaustive(all, first);
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.condition(|s| s.visit_expr(&e.cond));
        self.branch(|s| s.visit_block(&e.body));
    }

    fn visit_expr_closure(&mut self, c: &'ast syn::ExprClosure) {
        // A closure may run once, many times (iterator adapters over a possibly
        // empty collection) or never (stored and not called).
        self.branch(|s| s.visit_expr(&c.body));
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.visit_expr(&e.expr);
        if let (Some(name), Expr::Array(arr)) = (crate::syntax::pat_ident(&e.pat), crate::syntax::strip(&e.expr)) {
            let keys: Vec<String> = arr.elems.iter().filter_map(|el| key_id(&self.key_names(el))).collect();
            if keys.len() == arr.elems.len() {
                self.loop_keys.insert(name, keys);
            }
        }
        // The body may run zero times.
        self.branch(|s| s.visit_block(&e.body));
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if let Some((_, diverge)) = &init.diverge {
                // `let Some(x) = storage.get(..) else { panic!() };`
                self.condition(|s| s.visit_expr(&init.expr));
                self.visit_expr(diverge);
                return;
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if self.cond_depth > 0 && p.path.segments.len() == 1 {
            let name = p.path.segments[0].ident.to_string();
            if let Some(init) = self.bindings.get(&name, Span::of(p).start) {
                if self.expr_reads_storage(init) {
                    self.facts.init_guards.push(Span::of(p));
                    self.facts.init_guard_keys.push(self.read_key_in(init));
                }
            }
        }
        syn::visit::visit_expr_path(self, p);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = macro_name(mac);
        // Macros are not expanded, so an auth-like macro name is trusted.
        if is_auth_helper_name(&name, &self.opts.auth_functions) {
            self.push_auth(Span::of(&mac.path));
        }
        let args = macro_args(mac);
        if is_assert_macro(&name) {
            self.condition(|s| args.iter().for_each(|a| s.visit_expr(a)));
        } else {
            args.iter().for_each(|a| self.visit_expr(a));
        }
    }

    fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
        use syn::BinOp::*;
        // `==` / `!=` count too: `if roles.len() == MAX_ROLES { panic!() }` caps a list grown one at a time.
        if self.cond_depth > 0 && matches!(b.op, Lt(_) | Le(_) | Gt(_) | Ge(_) | Eq(_) | Ne(_)) {
            for side in [&*b.left, &*b.right] {
                if let Expr::MethodCall(m) = crate::syntax::strip(side) {
                    if m.method == "len" {
                        if let Some(name) = crate::syntax::as_local_ident(&m.receiver) {
                            self.facts.len_bounds.push(name);
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_binary(self, b);
    }

    // Nested function items are modelled separately.
    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
}

/// `true` if a key constructor takes a runtime value (`DataKey::Balance(user)`),
/// not only fixed ones: `Symbol::new(&e, ADMIN_KEY)` names a single key.
/// The first value of a raw `invoke_contract` argument list, i.e. the `from` of a `transfer`:
/// `vec![&e, from, ..]`, `(from, ..).into_val(&e)`, or a local bound to either.
fn first_invoke_arg(expr: &Expr, bindings: &Bindings<'_>, depth: usize) -> Option<Expr> {
    match crate::syntax::strip(expr) {
        Expr::Macro(m) if crate::syntax::macro_name(&m.mac) == "vec" => {
            crate::syntax::macro_args(&m.mac).into_iter().nth(1)
        }
        Expr::Tuple(t) => t.elems.first().cloned(),
        Expr::MethodCall(c) if c.method == "into_val" || c.method == "into" => {
            first_invoke_arg(&c.receiver, bindings, depth)
        }
        e if depth < 4 => {
            let local = crate::syntax::as_local_ident(e)?;
            let init = bindings.get(&local, Span::of(e).start)?;
            first_invoke_arg(init, bindings, depth + 1)
        }
        _ => None,
    }
}

fn call_takes_values(c: &syn::ExprCall) -> bool {
    fn fixed(e: &Expr) -> bool {
        match crate::syntax::strip(e) {
            Expr::Lit(_) => true,
            Expr::Path(p) if p.qself.is_none() => {
                let last = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                let is_const = last.len() > 1
                    && last.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
                is_const || (p.path.segments.len() == 1 && matches!(last.as_str(), "e" | "env" | "_env"))
            }
            Expr::MethodCall(m) if m.method == "clone" => fixed(&m.receiver),
            _ => false,
        }
    }
    c.args.iter().any(|a| !fixed(a))
}

/// Identity of a storage key family for matching writes to TTL extensions:
/// `Type::Variant` when the key names its enum (`DidKey::Doc` and `GdprKey::Doc`
/// differ), otherwise its most specific name.
pub fn key_id(names: &[String]) -> Option<String> {
    match names {
        [.., ty, variant] if ty.starts_with(|c: char| c.is_ascii_uppercase()) => Some(format!("{ty}::{variant}")),
        [.., last] => Some(last.clone()),
        [] => None,
    }
}
