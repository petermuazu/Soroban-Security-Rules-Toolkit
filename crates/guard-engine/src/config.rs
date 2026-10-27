//! `stellar-guard.toml` configuration.
//!
//! ```toml
//! fail-on = "warning"        # info | warning | error | never
//! min-confidence = "low"     # low | medium | high
//! include-tests = false
//! exclude = ["src/generated/**"]
//! auth-functions = ["require_operator"]
//!
//! [rules.SG-003]
//! severity = "error"
//!
//! [rules.SG-003.options]
//! amount-identifiers = ["qty"]
//!
//! [rules.SG-004]
//! enabled = false
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::finding::{Confidence, FailOn, Severity};

/// File names searched for, in order.
pub const CONFIG_FILE_NAMES: &[&str] = &["stellar-guard.toml", ".stellar-guard.toml"];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleConfig {
    pub enabled: Option<bool>,
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub options: toml::Table,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub fail_on: Option<FailOn>,
    pub min_confidence: Option<Confidence>,
    pub include_tests: Option<bool>,
    pub allow_parse_failures: Option<bool>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub auth_functions: Vec<String>,
    #[serde(default)]
    pub rules: BTreeMap<String, RuleConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        Self::parse(&text).map_err(|message| ConfigError::Parse { path: path.to_path_buf(), message })
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string().trim().to_string())
    }

    /// Looks for a config file in `dir`.
    pub fn find_in(dir: &Path) -> Option<PathBuf> {
        CONFIG_FILE_NAMES.iter().map(|n| dir.join(n)).find(|p| p.is_file())
    }
}

/// Fully resolved settings for one scan (config file merged with CLI flags).
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub fail_on: FailOn,
    pub min_confidence: Confidence,
    pub include_tests: bool,
    /// Files that cannot be parsed do not fail the scan.
    pub allow_parse_failures: bool,
    pub exclude: Vec<String>,
    pub auth_functions: Vec<String>,
    pub rules: BTreeMap<String, RuleConfig>,
    /// When set, only these rules run.
    pub only: Option<Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            fail_on: FailOn::default(),
            min_confidence: Confidence::Low,
            include_tests: false,
            allow_parse_failures: false,
            exclude: Vec::new(),
            auth_functions: Vec::new(),
            rules: BTreeMap::new(),
            only: None,
        }
    }
}

impl From<Config> for Settings {
    fn from(c: Config) -> Self {
        Settings {
            fail_on: c.fail_on.unwrap_or_default(),
            min_confidence: c.min_confidence.unwrap_or(Confidence::Low),
            include_tests: c.include_tests.unwrap_or(false),
            allow_parse_failures: c.allow_parse_failures.unwrap_or(false),
            exclude: c.exclude,
            auth_functions: c.auth_functions,
            rules: c.rules.into_iter().fold(BTreeMap::new(), |mut acc, (k, v)| {
                let entry: &mut RuleConfig = acc.entry(k.to_ascii_uppercase()).or_default();
                entry.enabled = v.enabled.or(entry.enabled);
                entry.severity = v.severity.or(entry.severity);
                entry.options.extend(v.options);
                acc
            }),
            only: None,
        }
    }
}

impl Settings {
    fn rule(&self, id: &str) -> Option<&RuleConfig> {
        self.rules.get(id)
    }

    pub fn rule_mut(&mut self, id: &str) -> &mut RuleConfig {
        self.rules.entry(id.to_ascii_uppercase()).or_default()
    }

    /// Whether rule `id` runs.
    pub fn is_enabled(&self, id: &str) -> bool {
        if let Some(only) = &self.only {
            if !only.iter().any(|o| o.eq_ignore_ascii_case(id)) {
                return false;
            }
        }
        self.rule(id).and_then(|r| r.enabled).unwrap_or(true)
    }

    /// The user-configured severity for rule `id`, if any.
    pub fn severity_override(&self, id: &str) -> Option<Severity> {
        self.rule(id).and_then(|r| r.severity)
    }

    pub fn options(&self, id: &str) -> toml::Table {
        self.rule(id).map(|r| r.options.clone()).unwrap_or_default()
    }
}

/// The documented default configuration, written by `stellar-guard init`.
pub const DEFAULT_CONFIG_TOML: &str = r#"# stellar-guard configuration
# Docs: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/configuration.md

# Minimum severity that makes `stellar-guard scan` exit with status 1.
# One of: "info", "warning", "error", "never".
fail-on = "warning"

# Hide findings below this confidence. One of: "low", "medium", "high".
min-confidence = "low"

# Analyze test code (`#[cfg(test)]`, `tests/`, `benches/`) as well.
include-tests = false

# Files stellar-guard cannot parse are not analyzed. By default they fail the scan (unless
# `fail-on = "never"`) so an unanalyzed file never passes CI silently.
allow-parse-failures = false

# Extra glob patterns to skip, relative to each scanned path.
exclude = []

# Project-specific helpers that perform authorization (treated like `require_auth`).
auth-functions = []

# Per-rule settings. Available rules: `stellar-guard rules`.
# [rules.SG-003]
# severity = "error"
#
# [rules.SG-003.options]
# amount-identifiers = ["qty"]
#
# [rules.SG-004]
# enabled = false
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let c = Config::parse(
            r#"
            fail-on = "error"
            min-confidence = "medium"
            exclude = ["gen/**"]
            [rules.sg-003]
            severity = "info"
            [rules.SG-003.options]
            amount-identifiers = ["qty"]
            [rules.SG-004]
            enabled = false
            "#,
        );
        // Mixed-case duplicate tables are both accepted by TOML; normalise in Settings.
        let s: Settings = c.unwrap().into();
        assert_eq!(s.severity_override("SG-003"), Some(Severity::Info));
        assert!(s.options("SG-003").contains_key("amount-identifiers"));
        assert_eq!(s.fail_on, FailOn::Error);
        assert_eq!(s.min_confidence, Confidence::Medium);
        assert!(!s.is_enabled("SG-004"));
        assert!(s.is_enabled("SG-001"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse("fail_on = \"error\"").unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
        assert!(Config::parse("[rules.SG-001]\nlevel = \"error\"").is_err());
        assert!(Config::parse("fail-on = \"sometimes\"").is_err());
    }

    #[test]
    fn default_config_is_valid() {
        let c = Config::parse(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(c.fail_on, Some(FailOn::Warning));
    }

    #[test]
    fn only_filter() {
        let s = Settings { only: Some(vec!["sg-002".into()]), ..Default::default() };
        assert!(s.is_enabled("SG-002"));
        assert!(!s.is_enabled("SG-001"));
    }
}
