# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Changes that make an existing rule report new findings
are listed under **Changed**.

## [Unreleased]

### Changed

- Packages are renamed for crates.io: the CLI package is `stellar-guard` (was `guard-cli`; use
  `-p stellar-guard`), libraries are `stellar-guard-*`. Rust import paths (`guard_engine`, …) are unchanged.
- SG-001 no longer trusts a helper because of its name alone (`require_admin`, `check_owner_auth`, …)
  when the crate defines it: the helper's body must actually authorize. Names are still trusted for
  helpers defined outside the crate.
- SG-001 reports upgrades, outflows and privileged writes whose only authorization runs on some code
  paths (inside an `if` without `else`, one `match` arm, or a loop body) with medium confidence.
- SG-003 treats `i128` / `u128` function parameters as token amounts regardless of name (medium
  confidence at most).
- SG-001 reports a balance debit keyed by an address that did not authorize
  (`caller.require_auth(); spend_balance(&e, &victim, amount)`), `require_auth_for_args` calls that
  sign none of the amounts or addresses, and balance debits behind conditional authorization. Auth
  inside closures counts as conditional. Contract upgrades through
  `deployer().update_current_contract(..)` are recognised.
- SG-002 reports a `Map`/`Vec` kept under one instance key that grows with caller-supplied entries.
- SG-003 tracks amounts through local variables and reports division before multiplication (info).
  Per-package `[profile.release.package.<name>] overflow-checks` overrides are honoured.
- SG-004 recognises length caps checked in helpers or where the storage key is written, under any
  variable name (4 fewer false positives on OpenZeppelin stellar-contracts).
- SG-005 reports initializer guards on a key the initializer never writes.
- SG-005 reports guarded initializers that can be front-run (warning): they authorize nobody, or
  only addresses passed in as arguments. Use `__constructor`.
- SG-007 checks persistent TTL extensions per key family: when a crate extends some persistent keys,
  each other key family written but never extended is reported. Keys are followed through helpers,
  `store(key, value)` wrappers and `for key in [..]` loops.
- Recall on independently reported bugs (`scripts/real_bugs.py`): 18 / 18 on the development set,
  11 / 21 on a held-out set before changes and 17 / 21 after (see `docs/validation.md`).
- SG-001 reports a storage write without authorization as a high-confidence warning when the
  function's comment says it is admin- or owner-only, and as a medium-confidence warning when the
  contract's other setters all authorize (previously both were low-confidence `info`). This turns
  Reflector V3's high-severity Code4rena finding (invocation costs settable by anyone) into a warning.
- Test-support crates (a regular dependency enables `testutils`, which cannot build for wasm) are
  excluded like other test code unless `--include-tests` is given.
- SG-002 treats keys built only from constants (`Symbol::new(e, ADMIN_KEY)`) as single keys, not
  per-user keys. SG-003 no longer treats enum variants cast to integers as token amounts. On the
  audited Blend v2 code this removes 24 of 33 warnings.
- SG-004 traces where a collection's length comes from: lists built element-wise from parameters or
  returned by cross-contract calls are no longer treated as storage-backed, `len() == MAX` counts as
  a cap, and lists derived from a capped stored list inherit the cap (OpenZeppelin stellar-contracts:
  10 → 3 warnings, recall unchanged at 12 / 12).
- Calls are resolved by module path, impl type and trait (`a::f`, `Self::f`, `<T as Tr>::f`), trait
  default methods are modelled, and helpers in local dependency crates of the same workspace are
  followed.
- Storage keys defined as constants (`const KEY: Symbol = symbol_short!("ADMIN")`) are resolved.
- Files starting with `#![cfg(test)]` and cargo-fuzz `fuzz_targets/` are treated as test code.
- Throughput is about 25% lower than 0.1.0 (see `docs/benchmarks.md`).

### Added

- Optional `scan --expand-macros` analysis via `cargo-expand`, with graceful fallback to source
  scanning when expansion is unavailable or fails.
- SG-010 `missing-admin-events` (info): exported privileged-key writes and contract upgrades
  without a Soroban event.
- SG-006 `negative-amount`: `i128` parameters written to storage without a sign check.
- SG-007 `missing-ttl-extension` (info): persistent / instance data whose TTL is never extended.
- SG-008 `ignored-try-call`: discarded results of `client.try_*` cross-contract calls.
- SG-009 `weak-check-auth` (error): custom-account `__check_auth` that verifies no signature, or a
  signature not bound to `signature_payload`.
- `scripts/seeded_bugs.py` recall check: 12 / 12 seeded bugs detected in soroban-examples (0.1.0:
  6 / 12). Real-world baseline updated in `docs/validation.md`.
- Golden-file tests for every report format (text, JSON, SARIF, GitHub, Markdown).
- JSON Schema for the report (`docs/report.schema.json`), checked against real output in tests.
- Distribution: crates are published as `stellar-guard` and `stellar-guard-{parser,engine,rules,reporters}`
  (`cargo install stellar-guard`, `cargo binstall stellar-guard`); a static Docker image
  (`ghcr.io/petermuazu/stellar-guard`); `stellar-guard` and `stellar-guard-docker` pre-commit hooks.
- Releases carry signed build provenance and a CycloneDX SBOM for every archive and the image.

## [0.1.0] - 2026-10-26

### Added

- `stellar-guard` CLI with `scan`, `rules`, `explain` and `init` subcommands.
- Rules:
  - SG-001 `missing-authorization`
  - SG-002 `storage-tier-misuse`
  - SG-003 `unchecked-arithmetic` (aware of `overflow-checks`)
  - SG-004 `unbounded-iteration`
  - SG-005 `unprotected-initializer`
- Crate-wide semantic model that follows helper functions transitively.
- Output formats: text, JSON (schema 1.0), SARIF 2.1.0, GitHub annotations, Markdown; multiple
  outputs per run with `--report FORMAT=PATH`.
- `stellar-guard.toml` configuration with strict validation, severity overrides, per-rule options
  and confidence filtering.
- Inline (`stellar-guard-ignore`) and file-level suppressions.
- Configurable exit codes via `--fail-on`.
- Deterministic reports with line-independent fingerprints.
- Vulnerable and safe fixture contracts (compile against soroban-sdk 22) with marker-driven tests.
- Real-world precision baseline on soroban-examples and OpenZeppelin stellar-contracts (`docs/validation.md`).
- GitHub Action with PR annotations, job summary and code-scanning upload.
- CI (fmt, clippy, tests on Linux/macOS/Windows, MSRV, docs, self-scan, action test, audit) and
  release workflows.

[Unreleased]: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/releases/tag/v0.1.0
