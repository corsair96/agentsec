use super::ScanReport;
use crate::score;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("# agentsec report\n\n");
    out.push_str(&format!(
        "**Risk score:** {:.1}/10 ({})\n\n",
        report.risk_score,
        score::label(report.risk_score)
    ));
    out.push_str(&format!("**Summary:** {}\n\n", report.summary_line()));

    let sources: Vec<String> = report
        .sources
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(layer, count)| format!("{}({count})", layer.as_str()))
        .collect();
    out.push_str(&format!(
        "**Sources scanned:** {}\n\n",
        if sources.is_empty() {
            "none".to_string()
        } else {
            sources.join(", ")
        }
    ));

    if report.findings.is_empty() {
        out.push_str("No security findings.\n");
        return out;
    }

    out.push_str("## Findings\n\n");
    for finding in &report.findings {
        out.push_str(&format!(
            "### {} {} — {}\n\n",
            finding.severity.emoji(),
            finding.severity.label(),
            finding.title
        ));
        out.push_str(&format!("- **Rule:** `{}`\n", finding.id));
        out.push_str(&format!(
            "- **Location:** `{}:{}`{}\n",
            finding.file,
            finding.line,
            finding
                .client
                .as_ref()
                .map(|client| format!(" ({client})"))
                .unwrap_or_default()
        ));
        out.push_str(&format!("- **Evidence:** `{}`\n", finding.evidence));
        if let Some(fix) = &finding.fix {
            out.push_str(&format!("- **Fix:** {fix}\n"));
        }
        let mut mappings = Vec::new();
        if let Some(llm) = &finding.owasp.llm {
            mappings.push(format!("LLM {llm}"));
        }
        if let Some(mcp) = &finding.owasp.mcp {
            mappings.push(format!("MCP {mcp}"));
        }
        if let Some(agentic) = &finding.owasp.agentic {
            mappings.push(format!("Agentic {agentic}"));
        }
        if !mappings.is_empty() {
            out.push_str(&format!("- **OWASP:** {}\n", mappings.join(", ")));
        }
        out.push('\n');
    }

    if let Some(diff) = &report.baseline_diff {
        out.push_str("## Baseline diff\n\n");
        out.push_str(&format!(
            "- New: {}\n- Resolved: {}\n- Unchanged: {}\n- Baseline total: {}\n",
            diff.new, diff.resolved, diff.unchanged, diff.baseline_total
        ));
    }

    out
}
