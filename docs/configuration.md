# Configuration

stellar-guard reads `stellar-guard.toml` (or `.stellar-guard.toml`) from the current directory, or
else from the first scanned directory that has one. Use `--config <file>` to choose a file and
`--no-config` to ignore config files. Create a documented default with:

```sh
stellar-guard init
```

Command-line flags always override the file.

## Reference

```toml
# Minimum severity that makes `scan` exit with status 1: "info" | "warning" | "error" | "never".
fail-on = "warning"

# Hide findings below this confidence: "low" | "medium" | "high".
min-confidence = "low"

# Analyze test code too (#[cfg(test)] items and files, tests/, benches/, fuzz_targets/, and
# test-support crates whose regular dependencies enable `testutils`).
include-tests = false

# Files that cannot be parsed are reported but not analyzed. By default they make `scan` exit with
# status 1 (unless fail-on = "never"), so an unanalyzed file never passes CI silently.
allow-parse-failures = false

# Extra glob patterns to skip, relative to each scanned path.
exclude = ["src/generated/**"]

# Project-specific functions/macros that perform authorization (used by SG-001 and the model).
auth-functions = ["require_operator", "assert_signer"]

[rules.SG-001]
enabled = true            # default: true
severity = "error"        # override the rule's default severity

[rules.SG-001.options]
ignore-functions = ["poke"]

[rules.SG-004]
enabled = false
```

Unknown keys, unknown rule IDs and unknown rule options are errors (exit code 2).

## Rule options

| Rule | Option | Type | Meaning |
|---|---|---|---|
| SG-001 | `ignore-functions` | list of strings | Exported functions that are intentionally permissionless |
| SG-001 | `privileged-keys` | list of strings | Extra storage-key words treated as privileged |
| SG-002 | `sensitive-keys` | list of strings | Extra key words meaning "long-lived state" |
| SG-002 | `ignore-keys` | list of strings | Extra key words meaning "fine to expire" |
| SG-003 | `amount-identifiers` | list of strings | Extra identifier words treated as token amounts |
| SG-005 | `initializer-names` | list of strings | Extra function names treated as initializers |

Words are matched case-insensitively against the `_`/camel-case words of identifiers, so
`"FeeRecipient"` adds the words `fee` and `recipient`.

## Command-line equivalents

| Config | Flag |
|---|---|
| `fail-on` | `--fail-on <level>` |
| `min-confidence` | `--min-confidence <level>` |
| `include-tests` | `--include-tests` |
| `allow-parse-failures` | `--allow-parse-failures` |
| `exclude` | `--exclude <glob>` (repeatable) |
| `auth-functions` | `--auth-fn <name>` (repeatable / comma separated) |
| `[rules.X] enabled = false` | `--disable X` |
| only run some rules | `--rule X,Y` |
| `[rules.X] severity` | `--severity X=error` |

## Inline suppressions

```rust
// stellar-guard-ignore SG-001 -- anyone may record a heartbeat; no value at risk
env.storage().instance().set(&DataKey::LastPoke, &now);

let total = a + b; // stellar-guard-ignore: SG-003

// stellar-guard-ignore             ← no IDs: suppresses every rule on the next statement

//! stellar-guard-ignore-file SG-004   ← whole file
```

* A comment on its own line applies to the next statement (attributes and comments in between are
  skipped; the statement ends at a line ending in `;`, `{` or `}`).
* A trailing comment applies to its own line.
* Text after `--` is a free-form reason. Please always give one.
* Suppressed findings are counted in the summary (`suppressed`) so they stay visible.
