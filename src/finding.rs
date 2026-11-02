use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn weight(self) -> f64 {
        match self {
            Severity::Low => 1.0,
            Severity::Medium => 2.0,
            Severity::High => 3.0,
            Severity::Critical => 4.0,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Severity::Low => "🔵",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }

    /// SARIF result level.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High | Severity::Critical => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Mcp,
    Agent,
    Model,
    Rag,
    Secrets,
    Skills,
}

impl Layer {
    pub const ALL: [Layer; 6] = [
        Layer::Mcp,
        Layer::Agent,
        Layer::Model,
        Layer::Rag,
        Layer::Secrets,
        Layer::Skills,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Mcp => "mcp",
            Layer::Agent => "agent",
            Layer::Model => "model",
            Layer::Rag => "rag",
            Layer::Secrets => "secrets",
            Layer::Skills => "skills",
        }
    }

    pub fn weight(self) -> f64 {
        match self {
            Layer::Mcp => 1.2,
            Layer::Agent => 1.0,
            Layer::Secrets => 1.1,
            Layer::Skills => 0.8,
            Layer::Rag => 0.9,
            Layer::Model => 1.0,
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Owasp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agentic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub source: Layer,
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    pub evidence: String,
    pub owasp: Owasp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    pub fixable: bool,
}

impl Finding {
    /// Stable fingerprint used by baseline / drift detection.
    pub fn fingerprint(&self) -> String {
        let input = format!("{}|{}|{}", self.id, self.file, self.evidence);
        fnv1a_hex(input.as_bytes())
    }
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
