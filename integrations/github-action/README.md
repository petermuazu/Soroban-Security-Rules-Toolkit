# stellar-guard GitHub Action

Runs [stellar-guard](../../README.md) on your Soroban contracts. It annotates pull requests, writes
a job summary, uploads SARIF to GitHub code scanning, and fails the job when findings meet your
threshold.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: petermuazu/Soroban-Security-Rules-Toolkit/integrations/github-action@main  # pin to a release tag once v0.1.0 is published
    with:
      path: contracts
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Files or directories to scan (space separated) |
| `fail-on` | `warning` | `info`, `warning`, `error` or `never` |
| `min-confidence` | *(config / `low`)* | Hide findings below `low`, `medium` or `high` confidence |
| `config` | *(auto)* | Path to a `stellar-guard.toml` |
| `args` | | Extra arguments for `stellar-guard scan`, e.g. `--disable SG-004 --exclude 'gen/**'` |
| `version` | *(build from source)* | Release tag (e.g. `v0.1.0`) to download a prebuilt binary instead of building |
| `sarif-file` | `stellar-guard.sarif` | Where to write the SARIF report |
| `upload-sarif` | `true` | Upload SARIF to code scanning (needs `security-events: write`) |
| `annotations` | `true` | Inline annotations on the PR diff |
| `job-summary` | `true` | Findings table on the job summary page |

## Outputs

| Output | Description |
|---|---|
| `exit-code` | `0` pass, `1` findings at or above `fail-on`, `2` error |
| `sarif-file` | Path of the SARIF report |

## Installation modes

* **Default:** the action builds stellar-guard from the action's own source with
  `cargo install --locked` (installing Rust if needed) and caches the binary, keyed on the source
  hash. The first run takes about a minute; cached runs take seconds.
* **`version: v0.1.0`** (available once that release is published): downloads the prebuilt binary for the runner (Linux x64/arm64, macOS
  x64/arm64, Windows x64) from the GitHub release.

## Notes

* Run from the repository root (the default) so SARIF paths match your files.
* Pull requests from forks cannot upload SARIF. Use
  `upload-sarif: ${{ github.event.pull_request.head.repo.fork != true }}`.
* A full sample workflow: [docs/examples/stellar-guard.yml](../../docs/examples/stellar-guard.yml).
