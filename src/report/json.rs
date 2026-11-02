use super::ScanReport;
use crate::finding::Severity;
use anyhow::Result;
use chrono::Utc;
use serde_json::json;

pub fn render(report: &ScanReport) -> Result<String> {
    let counts = report.severity_counts();
    let mut summary = serde_json::Map::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        let count = counts
            .iter()
            .find(|(candidate, _)| *candidate == severity)
            .map(|(_, count)| *count)
            .unwrap_or(0);
        summary.insert(severity.as_str().to_string(), json!(count));
    }

    let sources: Vec<&str> = report
        .sources
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(layer, _)| layer.as_str())
        .collect();

    let payload = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "risk_score": report.risk_score,
        "summary": summary,
        "sources_scanned": sources,
        "findings": report.findings,
        "baseline_diff": report.baseline_diff,
    });

    Ok(format!("{}\n", serde_json::to_string_pretty(&payload)?))
}
