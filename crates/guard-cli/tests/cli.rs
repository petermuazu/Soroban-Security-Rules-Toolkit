//! End-to-end tests of the `stellar-guard` binary.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn fixtures(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(sub)
}

fn bin() -> Command {
    let mut c = Command::cargo_bin("stellar-guard").unwrap();
    c.env_remove("NO_COLOR");
    c
}

fn scan(args: &[&str]) -> assert_cmd::assert::Assert {
    bin().arg("scan").arg("--no-config").args(args).assert()
}

#[test]
fn vulnerable_fixtures_exit_1() {
    scan(&[fixtures("vulnerable-examples").to_str().unwrap()])
        .code(1)
        .stdout(predicate::str::contains("warning[SG-001]"))
        .stdout(predicate::str::contains("error[SG-005]"))
        .stdout(predicate::str::contains("does not prove a contract is secure"));
}

#[test]
fn safe_fixtures_exit_0() {
    scan(&[fixtures("safe-contracts").to_str().unwrap()])
        .code(0)
        .stdout(predicate::str::contains("0 errors, 0 warnings"));
}

#[test]
fn fail_on_thresholds() {
    let vuln = fixtures("vulnerable-examples/missing-auth");
    let p = vuln.to_str().unwrap();
    scan(&[p, "--fail-on", "never"]).code(0);
    scan(&[p, "--fail-on", "error"]).code(0); // SG-001 is a warning
    scan(&[p, "--fail-on", "error", "--severity", "SG-001=error"]).code(1);
    let init = fixtures("vulnerable-examples/unprotected-init");
    scan(&[init.to_str().unwrap(), "--fail-on", "error"]).code(1);
}

#[test]
fn json_output_is_valid_and_deterministic() {
    let p = fixtures("vulnerable-examples");
    let run = || {
        let out = scan(&[p.to_str().unwrap(), "--format", "json", "--fail-on", "never", "-q"])
            .code(0)
            .get_output()
            .stdout
            .clone();
        String::from_utf8(out).unwrap()
    };
    let a = run();
    let b = run();
    assert_eq!(a, b, "reports must be reproducible");
    let v: Value = serde_json::from_str(&a).unwrap();
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["tool"]["name"], "stellar-guard");
    let findings = v["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 60);
    for f in findings {
        assert!(f["location"]["start_line"].as_u64().unwrap() > 0);
        assert_eq!(f["fingerprint"].as_str().unwrap().len(), 16);
    }
}

#[test]
fn sarif_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("nested/results.sarif");
    scan(&[
        fixtures("vulnerable-examples/unchecked-arithmetic").to_str().unwrap(),
        "--format",
        "sarif",
        "--output",
        out.to_str().unwrap(),
    ])
    .code(1)
    .stdout(predicate::str::is_empty())
    .stderr(predicate::str::contains("8 warnings"));
    let v: Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 11);
    assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), guard_rules::all().len());
}

#[test]
fn extra_reports() {
    let dir = tempfile::tempdir().unwrap();
    let sarif = dir.path().join("r.sarif");
    let md = dir.path().join("summary.md");
    scan(&[
        fixtures("vulnerable-examples/unprotected-init").to_str().unwrap(),
        "--format",
        "github",
        "--report",
        &format!("sarif={}", sarif.display()),
        "--report",
        &format!("markdown={}", md.display()),
    ])
    .code(1)
    .stdout(predicate::str::contains("::error file="));
    assert!(fs::read_to_string(sarif).unwrap().contains("\"SG-005\""));
    assert!(fs::read_to_string(md).unwrap().contains("| 🔴 error | [SG-005]"));
}

#[test]
fn rule_selection() {
    let p = fixtures("vulnerable-examples");
    let p = p.to_str().unwrap();
    let out = scan(&[p, "--rule", "SG-005", "-f", "json", "-q"]).get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert!(v["findings"].as_array().unwrap().iter().all(|f| f["rule_id"] == "SG-005"));
    assert_eq!(v["rules"].as_array().unwrap().len(), 1);

    let out =
        scan(&[p, "--disable", "SG-001,SG-002,SG-003,SG-004,SG-006,SG-007,SG-008,SG-009,SG-010", "-f", "json", "-q"])
            .get_output()
            .stdout
            .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 3);

    scan(&[p, "--rule", "SG-999"]).code(2).stderr(predicate::str::contains("unknown rule `SG-999`"));
}

#[test]
fn min_confidence_filter() {
    let p = fixtures("vulnerable-examples/missing-auth");
    let out = scan(&[p.to_str().unwrap(), "--min-confidence", "high", "--disable", "SG-010", "-f", "json", "-q"])
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    // `credit` is medium confidence and is filtered out.
    assert_eq!(v["findings"].as_array().unwrap().len(), 3);
}

#[test]
fn config_file_is_discovered_and_validated() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname=\"x\"\nversion=\"0.1.0\"\n[dependencies]\nsoroban-sdk=\"22\"\n",
    )
    .unwrap();
    fs::write(
        src.join("lib.rs"),
        "#[contractimpl] impl C { pub fn set(e: Env) { e.storage().instance().set(&K::Admin, &1); } }\n",
    )
    .unwrap();

    // Without config: SG-001 warning → exit 1.
    bin().current_dir(dir.path()).args(["scan", "."]).assert().code(1);

    fs::write(dir.path().join("stellar-guard.toml"), "[rules.SG-001]\nenabled = false\n").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["scan", ".", "-v"])
        .assert()
        .code(0)
        .stderr(predicate::str::contains("using config"));

    // CLI flag wins over config.
    fs::write(dir.path().join("stellar-guard.toml"), "fail-on = \"never\"\n").unwrap();
    bin().current_dir(dir.path()).args(["scan", "."]).assert().code(0);
    bin().current_dir(dir.path()).args(["scan", ".", "--fail-on", "warning"]).assert().code(1);

    // Typos are errors, not silently ignored.
    fs::write(dir.path().join("stellar-guard.toml"), "fail_on = \"never\"\n").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown field"));

    fs::write(dir.path().join("stellar-guard.toml"), "[rules.SG-003.options]\nbogus = [\"x\"]\n").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["scan", "."])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown option `bogus`"));
}

#[test]
fn errors_exit_2() {
    scan(&["/definitely/not/a/path"]).code(2).stderr(predicate::str::contains("does not exist"));
    let empty = tempfile::tempdir().unwrap();
    scan(&[empty.path().to_str().unwrap()]).code(2).stderr(predicate::str::contains("no Rust source files"));
    scan(&[".", "--format", "xml"]).code(2);
}

#[test]
fn parse_failures_are_reported_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("broken.rs"), "fn x( {").unwrap();
    fs::write(dir.path().join("ok.rs"), "use soroban_sdk::Env; fn y() {}").unwrap();
    scan(&[dir.path().to_str().unwrap()])
        .code(0)
        .stdout(predicate::str::contains("could not analyze"))
        .stdout(predicate::str::contains("1 file could not be parsed"));
}

#[test]
fn rules_explain_init() {
    bin().args(["rules"]).assert().success().stdout(predicate::str::contains("SG-004"));
    let out = bin().args(["rules", "--format", "json"]).assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), guard_rules::all().len());

    bin().args(["explain", "sg-003"]).assert().success().stdout(predicate::str::contains("amount-identifiers"));
    bin().args(["explain", "SG-123"]).assert().code(2);

    let dir = tempfile::tempdir().unwrap();
    bin().args(["init", dir.path().to_str().unwrap()]).assert().success();
    assert!(dir.path().join("stellar-guard.toml").exists());
    bin().args(["init", dir.path().to_str().unwrap()]).assert().code(2);
    bin().args(["init", "--force", dir.path().to_str().unwrap()]).assert().success();
}

#[test]
fn color_flag() {
    let p = fixtures("vulnerable-examples/unprotected-init");
    scan(&[p.to_str().unwrap(), "--color", "always"]).stdout(predicate::str::contains("\x1b["));
    scan(&[p.to_str().unwrap(), "--color", "never"]).stdout(predicate::str::contains("\x1b[").not());
}

#[test]
fn test_support_crates_are_skipped_unless_tests_are_included() {
    let d = tempfile::tempdir().unwrap();
    let suite = d.path().join("suite");
    fs::create_dir_all(suite.join("src")).unwrap();
    fs::write(
        suite.join("Cargo.toml"),
        "[package]\nname = \"suite\"\n[dependencies]\nsoroban-sdk = { version = \"22\", features = [\"testutils\"] }\n",
    )
    .unwrap();
    fs::copy(fixtures("vulnerable-examples/missing-auth/src/lib.rs"), suite.join("src/lib.rs")).unwrap();
    let p = suite.to_str().unwrap();
    scan(&[p]).code(2).stderr(predicate::str::contains("--include-tests"));
    scan(&[p, "--include-tests"]).code(1).stdout(predicate::str::contains("warning[SG-001]"));
}

#[test]
fn expand_macros_finds_macro_generated_storage_write_when_available() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"macro-contract\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("src/lib.rs"),
        "struct Env;\nstruct Storage;\nimpl Env { fn storage(&self) -> Storage { Storage } }\n\
impl Storage { fn temporary(&self) -> Self { Self } fn set<K, V>(&self, _: &K, _: &V) {} }\n\
enum DataKey { Admin }\n\
macro_rules! write_admin { ($e:expr) => { $e.storage().temporary().set(&DataKey::Admin, &1); }; }\n\
pub fn update(e: Env) { write_admin!(e); }\n",
    )
    .unwrap();

    let output = scan(&[dir.path().to_str().unwrap(), "--expand-macros", "--rule", "SG-002"]).get_output().clone();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("cargo-expand is not installed") || stderr.contains("cargo is not available") {
        assert_eq!(output.status.code(), Some(0));
    } else {
        assert_eq!(output.status.code(), Some(1), "{stderr}");
        assert!(stdout.contains("warning[SG-002]"), "{stdout}");
        assert!(stdout.contains("(cargo expand)"), "{stdout}");
    }
}
