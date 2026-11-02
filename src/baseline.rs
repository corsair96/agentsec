use crate::finding::Finding;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub timestamp: String,
    pub findings: Vec<BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub id: String,
    pub file: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub new: usize,
    pub resolved: usize,
    pub unchanged: usize,
    pub baseline_total: usize,
}

impl Baseline {
    pub fn fingerprints(&self) -> HashSet<String> {
        self.findings
            .iter()
            .map(|entry| entry.fingerprint.clone())
            .collect()
    }
}

pub fn load(path: &Path) -> Result<Baseline> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read baseline {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("cannot parse baseline {}", path.display()))
}

pub fn save(path: &Path, findings: &[Finding]) -> Result<()> {
    let baseline = Baseline {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        findings: findings
            .iter()
            .map(|finding| BaselineEntry {
                fingerprint: finding.fingerprint(),
                id: finding.id.clone(),
                file: finding.file.clone(),
                evidence: finding.evidence.clone(),
            })
            .collect(),
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }

    let content = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(path, format!("{content}\n"))
        .with_context(|| format!("cannot write baseline {}", path.display()))?;
    Ok(())
}

pub fn diff(findings: &[Finding], baseline: Option<&Baseline>) -> Option<BaselineDiff> {
    let baseline = baseline?;
    let known = baseline.fingerprints();
    let current: HashSet<String> = findings.iter().map(Finding::fingerprint).collect();

    let new = current.difference(&known).count();
    let resolved = known.difference(&current).count();
    let unchanged = current.intersection(&known).count();

    Some(BaselineDiff {
        new,
        resolved,
        unchanged,
        baseline_total: known.len(),
    })
}
