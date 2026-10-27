# stellar-guard — Soroban Security Rules Toolkit

[![CI](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/actions/workflows/ci.yml)
![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-blue)
![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

An open-source command-line tool that analyzes Stellar (Soroban) smart contract source code and
flags patterns that often lead to security problems, **before deployment**.

```console
$ stellar-guard scan ./contracts
warning[SG-001]: Exported function `withdraw` transfers tokens out of the contract without an authorization check
  --> contracts/vault/src/lib.rs:57:16
   |
57 |         client.transfer(&env.current_contract_address(), &user, &amount);
   |                ^^^^^^^^
   |
   = missing-authorization (SG-001), confidence: high, function: `withdraw`
   = help: Review whether this operation requires `address.require_auth()` (on the affected user or the stored admin). …
   = docs: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules/SG-001.md

stellar-guard scanned 12 files with 10 rules: 0 errors, 1 warning, 0 infos
note: stellar-guard reports potential issues found by source-level heuristics. Findings are not proof of a vulnerability, and a clean scan does not prove a contract is secure.
```

> [!IMPORTANT]
> **A clean scan does not prove a contract is secure.** stellar-guard is a source-level pattern
> detector. A finding is a prompt to review the code, not proof of a vulnerability. Use it alongside
> tests, fuzzing, code review and professional audits.

## Rules

| ID | Name | Default | Detects |
|---|---|---|---|
| [SG-001](docs/rules/SG-001.md) | `missing-authorization` | warning | Exported functions that write state, move funds out or upgrade the contract without `require_auth` |
| [SG-002](docs/rules/SG-002.md) | `storage-tier-misuse` | warning | Long-lived state (balances, admin…) in **temporary** storage; per-user data in **instance** storage |
| [SG-003](docs/rules/SG-003.md) | `unchecked-arithmetic` | warning | Plain `+ - *` and lossy `as` casts on token amounts (aware of `overflow-checks`) |
| [SG-004](docs/rules/SG-004.md) | `unbounded-iteration` | warning | Loops over storage-backed or caller-supplied collections without a bound |
| [SG-005](docs/rules/SG-005.md) | `unprotected-initializer` | error | `initialize`-style functions that can be called more than once |
| [SG-006](docs/rules/SG-006.md) | `negative-amount` | warning | `i128` amounts written to contract storage without rejecting negative values |
| [SG-007](docs/rules/SG-007.md) | `missing-ttl-extension` | info | Persistent / instance data whose TTL is never extended on-chain |
| [SG-008](docs/rules/SG-008.md) | `ignored-try-call` | warning | Discarded results of `client.try_*` cross-contract calls |
| [SG-009](docs/rules/SG-009.md) | `weak-check-auth` | error | Custom-account `__check_auth` that verifies no signature, or one not bound to the payload |
| [SG-010](docs/rules/SG-010.md) | `missing-admin-events` | info | Privileged writes and upgrades without a Soroban event |

Every rule follows helper functions across the crate (and into local dependency crates), reports a
**confidence** level, and is tested against both vulnerable and safe code. Each rule page lists its
known false positives and false negatives. [docs/validation.md](docs/validation.md) measures noise on
OpenZeppelin, soroban-examples and two audited codebases (Blend v2, Reflector V3), recall on
bugs seeded into real contracts, and recall on 39 bugs reported in GitHub issues of public
Soroban projects (held out: 11 / 21 before tuning, 17 / 21 after).

## Install

Prebuilt binary (Linux, macOS, Windows), from crates.io or with Docker (from v0.2.0):

```sh
cargo binstall stellar-guard                         # downloads the release binary
cargo install --locked stellar-guard                 # builds from crates.io (Rust 1.88+)
docker run --rm -v "$PWD:/src" ghcr.io/petermuazu/stellar-guard scan .
```

Or from the latest source:

```sh
cargo install --locked --git https://github.com/petermuazu/Soroban-Security-Rules-Toolkit stellar-guard
```

Archives are on the [releases page](https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/releases)
with SHA-256 checksums, a CycloneDX SBOM and signed build provenance:

```sh
gh attestation verify stellar-guard-v0.2.0-x86_64-unknown-linux-musl.tar.gz \
  --repo petermuazu/Soroban-Security-Rules-Toolkit
```

As a [pre-commit](https://pre-commit.com) hook:

```yaml
- repo: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit
  rev: v0.2.0
  hooks:
    - id: stellar-guard          # uses an installed binary
    # - id: stellar-guard-docker # or builds the Docker image; no Rust toolchain needed
```

## Usage

```sh
stellar-guard scan                                   # scan the current directory
stellar-guard scan contracts/ --fail-on error        # only errors fail the run
stellar-guard scan contracts/ --format json -o report.json
stellar-guard scan contracts/ --format sarif -o stellar-guard.sarif
stellar-guard scan contracts/ --rule SG-001,SG-005   # run selected rules
stellar-guard scan contracts/ --disable SG-004 --severity SG-003=error
stellar-guard scan contracts/ --min-confidence medium
stellar-guard rules                                  # list rules
stellar-guard explain SG-002                         # full rule documentation
stellar-guard init                                   # write a default stellar-guard.toml
```

| Exit code | Meaning |
|---|---|
| `0` | No finding at or above `--fail-on` (default `warning`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage, configuration or I/O error |

Output formats: `text` (default), `json`, `sarif`, `github` (PR annotations) and `markdown`.
Write several at once with `--report FORMAT=PATH`. See [docs/report-format.md](docs/report-format.md).

### Suppressing a finding

```rust
// stellar-guard-ignore SG-001 -- anyone may record a heartbeat; no value at risk
env.storage().instance().set(&DataKey::LastPoke, &now);
```

Suppressed findings are still counted in the summary. See [docs/configuration.md](docs/configuration.md).

## Configuration

`stellar-guard.toml` in your repository root:

```toml
fail-on = "warning"
min-confidence = "low"
exclude = ["src/generated/**"]
auth-functions = ["require_operator"]   # your own auth helpers

[rules.SG-003]
severity = "error"

[rules.SG-004]
enabled = false
```

Full reference: [docs/configuration.md](docs/configuration.md).

## CI

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: petermuazu/Soroban-Security-Rules-Toolkit/integrations/github-action@v0.1.0
    with:
      path: contracts
```

Findings appear as PR annotations, in the job summary and under **Security → Code scanning**.
See [docs/ci-integration.md](docs/ci-integration.md) and the
[sample workflow](docs/examples/stellar-guard.yml).

## How it works

stellar-guard parses source with [`syn`](https://docs.rs/syn); it does not compile your contract.
It builds a per-crate model of every function (contract exports, helpers, methods) with facts such
as storage reads/writes by tier and key, `require_auth` calls, outbound token transfers and WASM
upgrades. Rules query that model, following helpers transitively. Test code (`#[cfg(test)]`,
`tests/`) is skipped by default. Reports are deterministic: the same input produces byte-identical
output.

```
stellar-guard/
├── crates/
│   ├── guard-cli/          # `stellar-guard` binary, integration tests, benchmarks
│   ├── guard-parser/       # discovery, parsing, Cargo metadata, semantic model
│   ├── guard-engine/       # Rule trait, config, suppressions, findings, fingerprints
│   ├── guard-rules/        # SG-001 … SG-010
│   └── guard-reporters/    # text, JSON, SARIF, GitHub, Markdown
├── fixtures/
│   ├── safe-contracts/     # must produce zero findings
│   └── vulnerable-examples/ # every `// expect: SG-xxx` line must be reported
├── integrations/github-action/
└── docs/                   # rules/, architecture, configuration, report format, CI, benchmarks
```

Details: [docs/architecture.md](docs/architecture.md). Noise on real code: [docs/validation.md](docs/validation.md). Performance: about 0.6 ms per file
([docs/benchmarks.md](docs/benchmarks.md)).

## Limitations

* No type information; macro expansion is opt-in via `scan --expand-macros` and requires
  [`cargo-expand`](https://github.com/dtolnay/cargo-expand). Without it, rules rely on names and
  syntax and can miss renamed or indirect patterns, or flag safe code. Confidence levels reflect this.
* Helper functions are resolved by name within one crate; logic in other crates is not followed.
* Rules check that a protection *exists*, not that it is *correct* (e.g. that the right address
  is authorized).

## Contributing

New rules, fixtures and false-positive reports are very welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the rule checklist. To report a security issue in
stellar-guard itself, see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
