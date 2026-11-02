use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::util::{display_path, line_at, mask_secret, read_text};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

struct ProviderPattern {
    name: &'static str,
    rule: &'static str,
    regex: Regex,
}

static PROVIDER_PATTERNS: LazyLock<Vec<ProviderPattern>> = LazyLock::new(|| {
    vec![
        ProviderPattern {
            name: "Private key",
            rule: "SEC002",
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
                .expect("valid private key regex"),
        },
        ProviderPattern {
            name: "Anthropic API key",
            rule: "SEC001",
            regex: Regex::new(r"sk-ant-[A-Za-z0-9_\-]{20,}").expect("valid anthropic regex"),
        },
        ProviderPattern {
            name: "OpenAI API key",
            rule: "SEC001",
            regex: Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}").expect("valid openai regex"),
        },
        ProviderPattern {
            name: "AWS access key",
            rule: "SEC001",
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws regex"),
        },
        ProviderPattern {
            name: "GitHub token",
            rule: "SEC001",
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").expect("valid github regex"),
        },
        ProviderPattern {
            name: "Slack token",
            rule: "SEC001",
            regex: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").expect("valid slack regex"),
        },
        ProviderPattern {
            name: "Google API key",
            rule: "SEC001",
            regex: Regex::new(r"AIza[0-9A-Za-z_\-]{35}").expect("valid google regex"),
        },
        ProviderPattern {
            name: "JSON Web Token",
            rule: "SEC001",
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("valid jwt regex"),
        },
    ]
});

static GENERIC_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,})["']"#,
    )
    .expect("valid generic secret regex")
});

#[derive(Debug, Clone)]
pub(crate) struct SecretHit {
    pub start: usize,
    pub end: usize,
    pub name: &'static str,
    pub rule: &'static str,
    pub masked: String,
}

/// Detect credentials in a text blob.
///
/// `include_generic` enables the lower-confidence generic assignment rule.
pub(crate) fn secret_hits(text: &str, include_generic: bool) -> Vec<SecretHit> {
    let mut hits = Vec::new();

    for pattern in PROVIDER_PATTERNS.iter() {
        for matched in pattern.regex.find_iter(text) {
            let value = matched.as_str();
            if is_placeholder(value) {
                continue;
            }
            hits.push(SecretHit {
                start: matched.start(),
                end: matched.end(),
                name: pattern.name,
                rule: pattern.rule,
                masked: mask_secret(value),
            });
        }
    }

    // Keep the most specific / earliest provider match and drop overlaps
    // (the Anthropic pattern also matches the generic OpenAI shape).
    hits.sort_by_key(|hit| hit.start);
    let mut accepted: Vec<SecretHit> = Vec::new();
    for hit in hits {
        if accepted
            .iter()
            .any(|existing| hit.start < existing.end && existing.start < hit.end)
        {
            continue;
        }
        accepted.push(hit);
    }

    if include_generic {
        for matched in GENERIC_SECRET.find_iter(text) {
            if is_placeholder(matched.as_str()) {
                continue;
            }
            if accepted
                .iter()
                .any(|existing| matched.start() < existing.end && existing.start < matched.end())
            {
                continue;
            }
            accepted.push(SecretHit {
                start: matched.start(),
                end: matched.end(),
                name: "Generic secret",
                rule: "SEC003",
                masked: mask_secret(matched.as_str()),
            });
        }
    }

    accepted.sort_by_key(|hit| hit.start);
    accepted
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("your_")
        || lower.contains("your-")
        || lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("change_me")
        || lower.contains("redacted")
        || lower.contains("dummy")
        || lower.contains("sample")
        || lower.contains("xxxx")
        || lower.contains("${")
        || lower.contains("${{")
        || lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("os.getenv")
        || lower.contains("<")
        || lower.contains(">")
        || lower.contains("...")
}

pub fn scan(files: &[PathBuf]) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        // MCP configs are handled by the MCP scanner to avoid duplicate findings.
        if discovery::is_mcp_config(path) {
            continue;
        }

        let relevant = discovery::is_env_or_ci(path)
            || discovery::is_code(path)
            || discovery::is_config(path)
            || discovery::is_skill(path);

        if !relevant {
            continue;
        }

        let Some(text) = read_text(path) else {
            continue;
        };

        scanned += 1;
        let display = display_path(path);
        let include_generic =
            discovery::is_env_or_ci(path) || discovery::is_code(path) || discovery::is_config(path);

        for hit in secret_hits(&text, include_generic) {
            let evidence = format!("{}: {}", hit.name, hit.masked);
            findings.push(rules::make(
                hit.rule,
                display.clone(),
                line_at(&text, hit.start),
                evidence,
                None,
            ));
        }
    }

    (findings, scanned)
}
