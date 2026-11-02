use crate::finding::{Finding, Layer};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod agent;
pub mod mcp;
pub mod model;
pub mod rag;
pub mod secrets;
pub mod skills;

pub struct Outcome {
    pub findings: Vec<Finding>,
    pub counts: BTreeMap<Layer, usize>,
}

pub fn run(files: &[PathBuf], layers: &[Layer]) -> Outcome {
    let mut findings = Vec::new();
    let mut counts = BTreeMap::new();

    if layers.contains(&Layer::Mcp) {
        let (found, count) = mcp::scan(files);
        counts.insert(Layer::Mcp, count);
        findings.extend(found);
    }
    if layers.contains(&Layer::Agent) {
        let (found, count) = agent::scan(files);
        counts.insert(Layer::Agent, count);
        findings.extend(found);
    }
    if layers.contains(&Layer::Model) {
        let (found, count) = model::scan(files);
        counts.insert(Layer::Model, count);
        findings.extend(found);
    }
    if layers.contains(&Layer::Rag) {
        let (found, count) = rag::scan(files);
        counts.insert(Layer::Rag, count);
        findings.extend(found);
    }
    if layers.contains(&Layer::Secrets) {
        let (found, count) = secrets::scan(files);
        counts.insert(Layer::Secrets, count);
        findings.extend(found);
    }
    if layers.contains(&Layer::Skills) {
        let (found, count) = skills::scan(files);
        counts.insert(Layer::Skills, count);
        findings.extend(found);
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.id.cmp(&right.id))
    });

    Outcome { findings, counts }
}
