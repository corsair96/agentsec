use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::util::{display_path, line_at, read_text};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

static MODEL_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:ollama|openai|anthropic|vllm|lmstudio|text-generation|inference|llm|model)\b",
    )
    .expect("valid model marker regex")
});

static ENDPOINT_SETTING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:ollama_host|openai_base_url|anthropic_base_url|base_url|api_base|model_endpoint|inference_endpoint|host)\b\s*[:=]\s*["']?(?:http://[^\s"']+|0\.0\.0\.0(?::\d+)?)"#,
    )
    .expect("valid endpoint setting regex")
});

static BIND_ALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)0\.0\.0\.0(?::\d+)?|\bhost\s*[:=]\s*["']?(?:0\.0\.0\.0|\[::\])"#)
        .expect("valid bind-all regex")
});

pub fn scan(files: &[PathBuf]) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if !(discovery::is_config(path) || discovery::is_env_or_ci(path)) {
            continue;
        }
        let Some(text) = read_text(path) else {
            continue;
        };
        if !MODEL_MARKER.is_match(&text) {
            continue;
        }

        scanned += 1;
        let display = display_path(path);

        if let Some(matched) = ENDPOINT_SETTING.find(&text) {
            let value = matched.as_str();
            let exposed = BIND_ALL.is_match(value)
                || (value.to_ascii_lowercase().contains("http://")
                    && !value.contains("localhost")
                    && !value.contains("127.0.0.1")
                    && !value.contains("[::1]"));
            if exposed {
                findings.push(rules::make(
                    "MOD001",
                    display.clone(),
                    line_at(&text, matched.start()),
                    value,
                    None,
                ));
            }
        }
    }

    (findings, scanned)
}
