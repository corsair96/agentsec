use super::ScanReport;
use crate::finding::Severity;
use crate::score;

const WIDTH: usize = 67;

fn paint(value: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "1;31",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Low => "34",
    }
}

fn risk_color(label: &str) -> &'static str {
    match label {
        "CRITICAL" => "1;31",
        "HIGH" => "31",
        "MEDIUM" => "33",
        "LOW" => "34",
        _ => "32",
    }
}

fn elapsed(elapsed_ms: u128) -> String {
    if elapsed_ms >= 1000 {
        format!("{:.1}s", elapsed_ms as f64 / 1000.0)
    } else {
        format!("{elapsed_ms}ms")
    }
}

pub fn render(report: &ScanReport, color: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "  agentsec v{} — Unified AI Agent Security Scanner\n",
        env!("CARGO_PKG_VERSION")
    ));

    let sources: Vec<String> = report
        .sources
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(layer, count)| format!("{}({count})", layer.as_str()))
        .collect();

    if sources.is_empty() {
        out.push_str("  Scanning 0 sources\n");
    } else {
        out.push_str(&format!(
            "  Scanning {} sources: {}\n",
            sources.len(),
            sources.join(", ")
        ));
    }
    out.push_str(&format!(
        "  {} {}\n\n",
        paint("✓", "32", color),
        elapsed(report.elapsed_ms)
    ));

    let label = score::label(report.risk_score);
    let border = "─".repeat(WIDTH - 2);
    out.push_str(&format!("  ┌{border}┐\n"));

    let score_line = format!("  RISK SCORE: {:.1}/10  ({label})", report.risk_score);
    out.push_str(&format!(
        "  │{}│\n",
        pad_colored(&score_line, risk_color(label), color)
    ));

    let summary = report.summary_line();
    let summary_line = format!("  {summary}");
    out.push_str(&format!(
        "  │{}│\n",
        pad_colored(
            &summary_line,
            if report.findings.is_empty() {
                "32"
            } else {
                "1"
            },
            color
        )
    ));
    out.push_str(&format!("  └{border}┘\n"));

    if report.findings.is_empty() {
        out.push_str("\n  No security findings. Nice.\n");
    }

    for finding in &report.findings {
        out.push('\n');
        let label = format!("{:<9}", finding.severity.label());
        out.push_str(&format!(
            "  {} {} {}  {}\n",
            finding.severity.emoji(),
            paint(&label, severity_color(finding.severity), color),
            paint(&format!("{:<8}", finding.id), "1", color),
            finding.title
        ));

        let client = finding
            .client
            .as_ref()
            .map(|client| format!("  ({client})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "     {}{}\n",
            paint(&format!("{}:{}", finding.file, finding.line), "2", color),
            client
        ));
        out.push_str(&format!(
            "     {} {}\n",
            paint(">", "2", color),
            finding.evidence
        ));
        if let Some(fix) = &finding.fix {
            out.push_str(&format!("     {} {}\n", paint("Fix:", "2", color), fix));
        }
    }

    out
}

/// Pad a line to the box width, keeping ANSI escapes outside the padding count.
fn pad_colored(line: &str, code: &str, color: bool) -> String {
    let visible = line.chars().count();
    let padding = (WIDTH - 2).saturating_sub(visible);
    let mut padded = line.to_string();
    padded.push_str(&" ".repeat(padding));
    paint(&padded, code, color)
}
