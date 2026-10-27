//! `stellar-guard` command-line interface.
//!
//! Exit codes:
//! * `0` — scan completed and no finding met the `--fail-on` threshold
//! * `1` — scan completed and at least one finding met the threshold
//! * `2` — usage, configuration or I/O error

use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use guard_engine::{Confidence, Config, Engine, FailOn, Settings, Severity, DEFAULT_CONFIG_TOML, DISCLAIMER};
use guard_parser::{DiscoverOptions, Project};
use guard_reporters::{render, Format, RenderOptions};

const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "stellar-guard",
    version,
    about = "Static security analysis for Soroban (Stellar) smart contracts",
    long_about = "stellar-guard scans Soroban contract source code for patterns that often lead to \
security problems: missing authorization, misuse of storage tiers, unchecked arithmetic, unbounded \
iteration and re-callable initializers.\n\nFindings are heuristics, not proof of a vulnerability, and \
a clean scan does not prove a contract is secure.",
    after_help = "Exit codes: 0 = no failing findings, 1 = findings at or above --fail-on, 2 = error.\n\
Docs: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit"
)]
struct Cli {
    /// When to use colors in text output.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    color: ColorChoice,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Command {
    /// Scan contract sources and report findings.
    Scan(ScanArgs),
    /// List available rules.
    Rules {
        /// Output format.
        #[arg(long, short, value_parser = ["text", "json"], default_value = "text")]
        format: String,
    },
    /// Show the full documentation for a rule.
    Explain {
        /// Rule ID, e.g. SG-001.
        rule: String,
    },
    /// Write a default stellar-guard.toml to the current directory.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
        /// Directory to write the config into.
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Files or directories to scan.
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Output format: text, json, sarif, github, markdown.
    #[arg(long, short, default_value = "text", value_parser = parse_format)]
    format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Write an additional report, e.g. `--report sarif=results.sarif`. Repeatable.
    #[arg(long = "report", value_name = "FORMAT=PATH", value_parser = parse_report)]
    reports: Vec<(Format, PathBuf)>,

    /// Minimum severity that causes exit status 1: info, warning, error, never.
    #[arg(long, value_parser = parse_fail_on)]
    fail_on: Option<FailOn>,

    /// Hide findings below this confidence: low, medium, high.
    #[arg(long, value_parser = parse_confidence)]
    min_confidence: Option<Confidence>,

    /// Configuration file (default: stellar-guard.toml in the current directory or scan path).
    #[arg(long, short, conflicts_with = "no_config")]
    config: Option<PathBuf>,

    /// Ignore any configuration file.
    #[arg(long)]
    no_config: bool,

    /// Only run these rules (comma separated or repeated).
    #[arg(long = "rule", value_delimiter = ',')]
    only: Vec<String>,

    /// Disable these rules (comma separated or repeated).
    #[arg(long = "disable", value_delimiter = ',')]
    disable: Vec<String>,

    /// Override a rule's severity, e.g. `--severity SG-003=error`. Repeatable.
    #[arg(long = "severity", value_name = "RULE=LEVEL", value_parser = parse_severity_override)]
    severities: Vec<(String, Severity)>,

    /// Additional glob patterns to exclude (relative to each scan path). Repeatable.
    #[arg(long)]
    exclude: Vec<String>,

    /// Also analyze test code.
    #[arg(long)]
    include_tests: bool,

    /// Expand each Cargo crate with `cargo expand` before scanning.
    #[arg(long)]
    expand_macros: bool,

    /// Treat these functions as authorization checks (comma separated or repeated).
    #[arg(long = "auth-fn", value_delimiter = ',')]
    auth_functions: Vec<String>,

    /// Suppress the summary printed to stderr when writing to a file.
    #[arg(long, short)]
    quiet: bool,

    /// Print the configuration file used and timing information to stderr.
    #[arg(long, short)]
    verbose: bool,
}

fn parse_format(s: &str) -> Result<Format, String> {
    s.parse()
}
fn parse_fail_on(s: &str) -> Result<FailOn, String> {
    s.parse()
}
fn parse_confidence(s: &str) -> Result<Confidence, String> {
    s.parse()
}
fn parse_report(s: &str) -> Result<(Format, PathBuf), String> {
    let (f, p) = s.split_once('=').ok_or_else(|| format!("expected FORMAT=PATH, got `{s}`"))?;
    if p.is_empty() {
        return Err("report path is empty".into());
    }
    Ok((f.parse()?, PathBuf::from(p)))
}
fn parse_severity_override(s: &str) -> Result<(String, Severity), String> {
    let (r, l) = s.split_once('=').ok_or_else(|| format!("expected RULE=LEVEL, got `{s}`"))?;
    Ok((r.trim().to_ascii_uppercase(), l.trim().parse()?))
}

fn engine() -> Engine {
    Engine::new(guard_rules::all()).with_tool("stellar-guard", env!("CARGO_PKG_VERSION"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = match cli.color {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };
    let result = match cli.command {
        Command::Scan(args) => scan(args, color),
        Command::Rules { format } => list_rules(&format).map(|_| ExitCode::SUCCESS),
        Command::Explain { rule } => explain(&rule).map(|_| ExitCode::SUCCESS),
        Command::Init { force, dir } => init(&dir, force).map(|_| ExitCode::SUCCESS),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn find_config(args: &ScanArgs) -> Option<PathBuf> {
    if args.no_config {
        return None;
    }
    if let Some(c) = &args.config {
        return Some(c.clone());
    }
    let cwd = std::env::current_dir().ok();
    cwd.iter()
        .map(PathBuf::as_path)
        .chain(args.paths.iter().filter(|p| p.is_dir()).map(PathBuf::as_path))
        .find_map(Config::find_in)
}

fn build_settings(args: &ScanArgs, config_path: Option<&Path>) -> Result<Settings> {
    let mut settings: Settings = match config_path {
        Some(p) => Config::load(p)?.into(),
        None => Settings::default(),
    };
    if let Some(f) = args.fail_on {
        settings.fail_on = f;
    }
    if let Some(c) = args.min_confidence {
        settings.min_confidence = c;
    }
    if args.include_tests {
        settings.include_tests = true;
    }
    settings.exclude.extend(args.exclude.iter().cloned());
    settings.auth_functions.extend(args.auth_functions.iter().cloned());
    if !args.only.is_empty() {
        settings.only = Some(args.only.iter().map(|s| s.trim().to_ascii_uppercase()).collect());
    }
    for id in &args.disable {
        settings.rule_mut(id.trim()).enabled = Some(false);
    }
    for (id, sev) in &args.severities {
        settings.rule_mut(id).severity = Some(*sev);
    }
    Ok(settings)
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn expand_macros(project: &mut Project, include_tests: bool) {
    let mut outside_cargo_package = false;
    for crate_id in 0..project.crates.len() {
        if !project.files.iter().any(|file| file.crate_id == crate_id) {
            continue;
        }
        let Some(root) = project.crates[crate_id].root.clone() else {
            outside_cargo_package = true;
            continue;
        };
        let output = match ProcessCommand::new("cargo").arg("expand").current_dir(&root).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("stellar-guard: cargo is not available; scanning unexpanded source");
                return;
            }
            Err(error) => {
                eprintln!(
                    "stellar-guard: could not run cargo expand in {}: {error}; scanning unexpanded source",
                    root.display()
                );
                continue;
            }
        };
        if !output.status.success() {
            let message =
                format!("{}{}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout));
            let lower = message.to_ascii_lowercase();
            if (lower.contains("no such command") && lower.contains("expand"))
                || lower.contains("could not find `expand`")
            {
                eprintln!("stellar-guard: cargo-expand is not installed; scanning unexpanded source");
                return;
            }
            eprintln!(
                "stellar-guard: cargo expand failed in {}: {}; scanning unexpanded source",
                root.display(),
                message.trim()
            );
            continue;
        }
        let expanded = String::from_utf8_lossy(&output.stdout);
        if expanded.trim().is_empty() {
            eprintln!(
                "stellar-guard: cargo expand produced no source in {}; scanning unexpanded source",
                root.display()
            );
            continue;
        }
        if let Err(error) = project.replace_crate_with_expanded_source(crate_id, &expanded, include_tests) {
            eprintln!(
                "stellar-guard: could not parse expanded source for {}: {}; scanning unexpanded source",
                root.display(),
                error.message
            );
        }
    }
    if outside_cargo_package {
        eprintln!("stellar-guard: sources outside Cargo packages were scanned without macro expansion");
    }
}

fn scan(args: ScanArgs, color: bool) -> Result<ExitCode> {
    let started = Instant::now();
    let config_path = find_config(&args);
    let settings = build_settings(&args, config_path.as_deref())?;
    if args.verbose {
        match &config_path {
            Some(p) => eprintln!("stellar-guard: using config {}", p.display()),
            None => eprintln!("stellar-guard: no config file, using defaults"),
        }
    }

    let analyzer = engine();
    let report = if args.expand_macros {
        analyzer.validate(&settings)?;
        let discover = DiscoverOptions { exclude: settings.exclude.clone(), include_tests: settings.include_tests };
        let mut project = Project::load(&args.paths, &discover)?;
        if project.files.is_empty() && project.failures.is_empty() {
            let shown: Vec<_> = args.paths.iter().map(|p| p.display().to_string()).collect();
            bail!(
                "no Rust source files found in {} (test code is skipped unless --include-tests is given)",
                shown.join(", ")
            );
        }
        expand_macros(&mut project, settings.include_tests);
        analyzer.scan_project(&project, &settings)
    } else {
        analyzer.scan(&args.paths, &settings)?
    };

    let to_stdout = args.output.is_none();
    let main_opts = RenderOptions { color: color && to_stdout && args.format == Format::Text };
    let rendered = render(&report, args.format, &main_opts);
    match &args.output {
        Some(path) => write_file(path, &rendered)?,
        None => {
            let mut stdout = std::io::stdout().lock();
            // A closed pipe (e.g. `| head`) is not an error worth reporting.
            let _ = stdout.write_all(rendered.as_bytes());
            let _ = stdout.flush();
        }
    }
    for (format, path) in &args.reports {
        write_file(path, &render(&report, *format, &RenderOptions::default()))?;
    }

    let fails = report.fails(settings.fail_on);
    if !args.quiet && (args.output.is_some() || args.format != Format::Text) {
        let s = &report.summary;
        eprintln!(
            "stellar-guard: {} files scanned, {} errors, {} warnings, {} infos, {} suppressed{}",
            s.files_scanned,
            s.errors,
            s.warnings,
            s.infos,
            s.suppressed,
            if s.parse_failures > 0 { format!(", {} parse failures", s.parse_failures) } else { String::new() }
        );
    }
    if args.verbose {
        eprintln!("stellar-guard: finished in {:.2?}", started.elapsed());
    }
    Ok(if fails { ExitCode::from(EXIT_FINDINGS) } else { ExitCode::SUCCESS })
}

fn list_rules(format: &str) -> Result<()> {
    let engine = engine();
    if format == "json" {
        let rules: Vec<_> = engine.rules().iter().map(|r| r.meta().info(r.meta().default_severity)).collect();
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }
    println!("{:<8} {:<9} {:<26} SUMMARY", "ID", "SEVERITY", "NAME");
    for r in engine.rules() {
        let m = r.meta();
        println!("{:<8} {:<9} {:<26} {}", m.id, m.default_severity.as_str(), m.name, m.summary);
    }
    println!("\nRun `stellar-guard explain <ID>` for details.");
    Ok(())
}

fn explain(id: &str) -> Result<()> {
    let engine = engine();
    let Some(rule) = engine.find_rule(id) else {
        bail!("unknown rule `{id}` (run `stellar-guard rules` to list rules)");
    };
    let m = rule.meta();
    println!("{} {} — {}", m.id, m.name, m.summary);
    println!("Default severity: {}", m.default_severity);
    println!("Tags: {}\n", m.tags.join(", "));
    println!("What it detects:\n  {}\n", m.description);
    println!("How to fix:\n  {}\n", m.remediation);
    if !m.options.is_empty() {
        println!("Options ([rules.{}.options] in stellar-guard.toml):", m.id);
        for o in m.options {
            println!("  {} (default {}): {}", o.name, o.default, o.description);
        }
        println!();
    }
    println!("Suppress a finding: // stellar-guard-ignore {} -- <reason>", m.id);
    println!("Docs: {}\n", m.help_uri());
    println!("{DISCLAIMER}");
    Ok(())
}

fn init(dir: &Path, force: bool) -> Result<()> {
    let path = dir.join("stellar-guard.toml");
    if path.exists() && !force {
        bail!("{} already exists (use --force to overwrite)", path.display());
    }
    write_file(&path, DEFAULT_CONFIG_TOML)?;
    println!("wrote {}", path.display());
    Ok(())
}
