mod baseline;
mod cli;
mod discovery;
mod finding;
mod report;
mod rules;
mod scanners;
mod score;
mod util;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{
    BaselineAction, BaselineArgs, Cli, Commands, InitArgs, OutputFormat, ProbeArgs, ScanArgs,
};
use finding::{Finding, Layer};
use report::ScanReport;
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

fn main() {
    // Restore default SIGPIPE behaviour so `agentsec ... | head` exits quietly.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("agentsec: {error:#}");
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Scan(args) => cmd_scan(args),
        Commands::Baseline(args) => cmd_baseline(args),
        Commands::ListRules => cmd_list_rules(),
        Commands::Init(args) => cmd_init(args),
        Commands::Probe(args) => cmd_probe(args),
        Commands::Version => {
            println!("agentsec {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}

fn cmd_scan(args: ScanArgs) -> Result<i32> {
    let started = Instant::now();
    let layers = args.layers();
    validate_timeout(&args.timeout)?;

    if args.verbose > 0 {
        eprintln!(
            "scanning {} (layers: {}, timeout: {})",
            args.path.display(),
            layers
                .iter()
                .map(|layer| layer.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            args.timeout
        );
    }

    let files = discovery::collect(&args.path, args.auto);
    if args.verbose > 0 {
        eprintln!("discovered {} candidate files", files.len());
    }

    let outcome = scanners::run(&files, &layers);
    let mut findings: Vec<Finding> = outcome
        .findings
        .into_iter()
        .filter(|finding| finding.severity >= args.min_severity)
        .collect();

    let loaded_baseline = match &args.baseline {
        Some(path) => Some(baseline::load(path)?),
        None => None,
    };
    let baseline_fingerprints: HashSet<String> = loaded_baseline
        .as_ref()
        .map(baseline::Baseline::fingerprints)
        .unwrap_or_default();

    let risk_score = score::compute(&findings, &baseline_fingerprints);
    let baseline_diff = baseline::diff(&findings, loaded_baseline.as_ref());

    if let Some(path) = &args.baseline_save {
        baseline::save(path, &findings)?;
        eprintln!("baseline saved to {}", path.display());
    }

    if args.apply_fix {
        eprintln!("agentsec: --apply-fix is not available in this build; running in dry-run mode");
    }
    if args.fix {
        let fixable = findings.iter().filter(|finding| finding.fixable).count();
        eprintln!("fix: {fixable} mechanical fix(es) available");
    }

    findings.shrink_to_fit();
    let report = ScanReport {
        findings,
        risk_score,
        sources: outcome.counts.into_iter().collect(),
        elapsed_ms: started.elapsed().as_millis(),
        baseline_diff,
    };

    let rendered = report::render(&report, args.format, !args.no_color)?;
    match &args.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("cannot create {}", parent.display()))?;
                }
            }
            std::fs::write(path, rendered)
                .with_context(|| format!("cannot write {}", path.display()))?;
            if args.verbose > 0 {
                eprintln!("report written to {}", path.display());
            }
        }
        None => print!("{rendered}"),
    }

    if args.format == OutputFormat::Terminal {
        let hits = report
            .findings
            .iter()
            .filter(|finding| finding.severity >= args.fail_on)
            .count();
        println!(
            "\n  Exit code: {} (fail-on: {})",
            i32::from(hits > 0),
            args.fail_on.as_str()
        );
    }

    let failed = report
        .findings
        .iter()
        .any(|finding| finding.severity >= args.fail_on);
    Ok(i32::from(failed))
}

fn cmd_baseline(args: BaselineArgs) -> Result<i32> {
    match args.action {
        BaselineAction::Save { output, path } => {
            let findings = static_scan(&path)?;
            baseline::save(&output, &findings)?;
            eprintln!(
                "baseline saved to {} ({} findings)",
                output.display(),
                findings.len()
            );
            Ok(0)
        }
        BaselineAction::Check { baseline, path } => {
            let loaded = baseline::load(&baseline)?;
            let known = loaded.fingerprints();
            let findings = static_scan(&path)?;
            let current: HashSet<String> = findings.iter().map(Finding::fingerprint).collect();

            let mut new_findings: Vec<&Finding> = findings
                .iter()
                .filter(|finding| !known.contains(&finding.fingerprint()))
                .collect();
            new_findings.sort_by(|left, right| {
                right
                    .severity
                    .cmp(&left.severity)
                    .then_with(|| left.file.cmp(&right.file))
            });

            let resolved = known.difference(&current).count();
            println!("Baseline: {}", baseline.display());
            println!("  new:       {}", new_findings.len());
            println!("  resolved:  {resolved}");
            println!("  unchanged: {}", current.intersection(&known).count());
            for finding in &new_findings {
                println!(
                    "  + {} {} {}:{} — {}",
                    finding.severity.label(),
                    finding.id,
                    finding.file,
                    finding.line,
                    finding.title
                );
            }
            Ok(i32::from(!new_findings.is_empty()))
        }
        BaselineAction::Diff { baseline, path } => {
            let loaded = baseline::load(&baseline)?;
            let known = loaded.fingerprints();
            let findings = static_scan(&path)?;
            let current: HashSet<String> = findings.iter().map(Finding::fingerprint).collect();

            println!("Baseline: {}", baseline.display());
            println!("  baseline total: {}", known.len());
            println!("  current total:  {}", current.len());
            println!("  new:            {}", current.difference(&known).count());
            println!("  resolved:       {}", known.difference(&current).count());
            println!("  unchanged:      {}", current.intersection(&known).count());
            Ok(0)
        }
    }
}

fn static_scan(path: &Path) -> Result<Vec<Finding>> {
    let files = discovery::collect(path, false);
    let outcome = scanners::run(&files, &Layer::ALL);
    Ok(outcome.findings)
}

fn cmd_list_rules() -> Result<i32> {
    println!("{:<8} {:<9} {:<8} TITLE", "ID", "SEVERITY", "LAYER");
    println!("{}", "-".repeat(94));
    for rule in rules::RULES {
        println!(
            "{:<8} {:<9} {:<8} {}",
            rule.id,
            rule.severity.as_str(),
            rule.layer.as_str(),
            rule.title
        );
        println!("         {}", rule.description);
        println!("         Fix: {}", rule.fix);
    }
    Ok(0)
}

fn cmd_init(args: InitArgs) -> Result<i32> {
    let target = if args.path.is_dir() {
        args.path.join("agentsec.yaml")
    } else {
        args.path
    };

    if target.exists() && !args.force {
        bail!(
            "{} already exists (use --force to overwrite)",
            target.display()
        );
    }

    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }

    let template = r#"# agentsec configuration
version: 1

scan:
  # Layers: mcp, agent, model, rag, secrets, skills
  layers:
    - mcp
    - agent
    - model
    - rag
    - secrets
    - skills
  min_severity: low
  fail_on: high
  exclude: []

baseline:
  # Path used by `agentsec scan --baseline`
  path: agentsec-baseline.json

rules:
  # Rule IDs to disable for this project.
  disable: []
"#;

    std::fs::write(&target, template)
        .with_context(|| format!("cannot write {}", target.display()))?;
    println!("created {}", target.display());
    Ok(0)
}

fn validate_timeout(value: &str) -> Result<()> {
    let value = value.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());

    if split == 0 {
        bail!("invalid --timeout value: {value:?} (expected e.g. 30s, 500ms, 2m)");
    }

    let (number, unit) = value.split_at(split);
    let number: u64 = number
        .parse()
        .with_context(|| format!("invalid --timeout value: {value:?}"))?;

    if number == 0 || !matches!(unit, "" | "ms" | "s" | "m" | "h") {
        bail!("invalid --timeout value: {value:?} (expected e.g. 30s, 500ms, 2m)");
    }

    Ok(())
}

fn cmd_probe(args: ProbeArgs) -> Result<i32> {
    match args.endpoint {
        Some(endpoint) => eprintln!(
            "agentsec: dynamic probing is not implemented in v{} (endpoint: {endpoint})",
            env!("CARGO_PKG_VERSION")
        ),
        None => eprintln!(
            "agentsec: dynamic probing is not implemented in v{}",
            env!("CARGO_PKG_VERSION")
        ),
    }
    Ok(0)
}
