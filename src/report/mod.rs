use crate::baseline::BaselineDiff;
use crate::cli::OutputFormat;
use crate::finding::{Finding, Layer, Severity};
use crate::score;
use anyhow::Result;

mod html;
mod json;
mod markdown;
mod sarif;
mod terminal;

pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub risk_score: f64,
    pub sources: Vec<(Layer, usize)>,
    pub elapsed_ms: u128,
    pub baseline_diff: Option<BaselineDiff>,
}

impl ScanReport {
    pub fn severity_counts(&self) -> [(Severity, usize); 4] {
        score::counts(&self.findings)
    }

    pub fn summary_line(&self) -> String {
        let counts = self.severity_counts();
        let total: usize = counts.iter().map(|(_, count)| count).sum();
        if total == 0 {
            return "No findings".to_string();
        }
        let parts: Vec<String> = counts
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(severity, count)| format!("{count} {}", severity.as_str()))
            .collect();
        let noun = if total == 1 { "finding" } else { "findings" };
        format!("{total} {noun}: {}", parts.join(", "))
    }
}

pub fn render(report: &ScanReport, format: OutputFormat, no_color: bool) -> Result<String> {
    match format {
        OutputFormat::Terminal => Ok(terminal::render(report, no_color)),
        OutputFormat::Json => json::render(report),
        OutputFormat::Markdown => Ok(markdown::render(report)),
        OutputFormat::Sarif => sarif::render(report),
        OutputFormat::Html => Ok(html::render(report)),
    }
}
