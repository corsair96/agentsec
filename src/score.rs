use crate::finding::{Finding, Severity};
use std::collections::HashSet;

/// Compute the 0-10 risk score described in PLAN.md.
///
/// score = sum(weight_severity * weight_layer * novelty_factor) / max_possible * 10
/// max_possible is the score if every finding were CRITICAL in the MCP layer.
pub fn compute(findings: &[Finding], baseline: &HashSet<String>) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    let numerator: f64 = findings
        .iter()
        .map(|finding| {
            let novelty = if baseline.contains(&finding.fingerprint()) {
                0.5
            } else {
                1.0
            };
            finding.severity.weight() * finding.source.weight() * novelty
        })
        .sum();

    let max_possible = 4.0 * 1.2 * findings.len() as f64;
    let score = (numerator / max_possible * 10.0).clamp(0.0, 10.0);
    (score * 10.0).round() / 10.0
}

pub fn label(score: f64) -> &'static str {
    if score >= 8.0 {
        "CRITICAL"
    } else if score >= 6.0 {
        "HIGH"
    } else if score >= 3.5 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "NONE"
    }
}

pub fn counts(findings: &[Finding]) -> [(Severity, usize); 4] {
    let mut counts = [
        (Severity::Critical, 0usize),
        (Severity::High, 0),
        (Severity::Medium, 0),
        (Severity::Low, 0),
    ];
    for finding in findings {
        if let Some((_, count)) = counts
            .iter_mut()
            .find(|(severity, _)| *severity == finding.severity)
        {
            *count += 1;
        }
    }
    counts
}
