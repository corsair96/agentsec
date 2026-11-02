use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::util::{display_path, line_at, read_text};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

static SHELL_EXECUTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\bsubprocess\.(?:run|call|popen|check_output|check_call)\b|\bos\.(?:system|popen)\b|\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bexecFileSync\b|\bRuntime\.getRuntime\(\)\.exec\b|\bshell\s*=\s*True\b"#,
    )
    .expect("valid shell execution regex")
});

static UNRESTRICTED_FS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:allowed_paths?|allow(?:ed)?_dirs?|root_dir|base_dir|workspace_dir|filesystem_root)\s*[:=]\s*(?:\[[^\]]*)?["'](?:\*|/|/\*|\*\*)["']|allow_all_paths\s*[:=]\s*(?:True|true)"#,
    )
    .expect("valid unrestricted filesystem regex")
});

static AUTO_APPROVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)auto_?approve\s*[:=]\s*(?:True|true)|human_?in_?the_?loop\s*[:=]\s*(?:False|false)|require_?approval\s*[:=]\s*(?:False|false)|dangerously-skip-permissions"#,
    )
    .expect("valid auto approve regex")
});

const AGENT_MARKERS: &[&str] = &[
    "langgraph",
    "crewai",
    "autogen",
    "langchain",
    "openai",
    "anthropic",
    "agent",
    "llm",
    "mcp",
    "tool",
];

pub fn scan(files: &[PathBuf]) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if !discovery::is_code(path) {
            continue;
        }
        let Some(text) = read_text(path) else {
            continue;
        };

        let lower = text.to_ascii_lowercase();
        if !AGENT_MARKERS.iter().any(|marker| lower.contains(marker)) {
            continue;
        }

        scanned += 1;
        let display = display_path(path);

        if let Some(matched) = SHELL_EXECUTION.find(&text) {
            findings.push(rules::make(
                "AGT001",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }

        if let Some(matched) = UNRESTRICTED_FS.find(&text) {
            findings.push(rules::make(
                "AGT003",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }

        if let Some(matched) = AUTO_APPROVE.find(&text) {
            findings.push(rules::make(
                "AGT004",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }
    }

    (findings, scanned)
}
