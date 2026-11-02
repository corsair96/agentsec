use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::util::{display_path, line_at, read_text};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s\)\]\}"'<>]+"#).expect("valid URL regex"));

static DANGEROUS_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:curl|wget)\b[^\n|]{0,240}\|\s*(?:ba|z|fi)?sh\b|\brm\s+-rf\s+/(?:\s|$)|\bchmod\s+777\b|\bsudo\b|\beval\b|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,120}\|\s*(?:ba|z|fi)?sh\b|\bnc\s+-e\b|\bpowershell(?:\.exe)?\s+-(?:enc|encodedcommand)\b"#,
    )
    .expect("valid dangerous command regex")
});

static PROMPT_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|(?:exfiltrate|leak)\b|send\b[^\n]{0,80}\bto\s+https?://|do\s+not\s+(?:tell|inform|mention)|bypass\s+(?:safety|policy|guardrail)"#,
    )
    .expect("valid prompt injection regex")
});

static SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:~|\$home|\$\{home\})/(?:\.ssh|\.aws|\.gnupg|\.config)|/etc/(?:passwd|shadow)|(?:^|[/\\])\.env\b|id_(?:rsa|ed25519)|(?:^|[/\\])\.npmrc\b|(?:^|[/\\])\.pypirc\b",
    )
    .expect("valid sensitive path regex")
});

pub fn scan(files: &[PathBuf]) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if !discovery::is_skill(path) {
            continue;
        }
        let Some(text) = read_text(path) else {
            continue;
        };
        scanned += 1;
        let display = display_path(path);

        // ---------------------------------------------------------- SKL001
        let mut urls = 0;
        for matched in URL.find_iter(&text) {
            let url = matched.as_str();
            if url.contains("localhost") || url.contains("127.0.0.1") || url.contains("[::1]") {
                continue;
            }
            findings.push(rules::make(
                "SKL001",
                display.clone(),
                line_at(&text, matched.start()),
                url,
                None,
            ));
            urls += 1;
            if urls >= 3 {
                break;
            }
        }

        // ---------------------------------------------------------- SKL002
        if let Some(matched) = DANGEROUS_COMMAND.find(&text) {
            findings.push(rules::make(
                "SKL002",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }

        // ---------------------------------------------------------- SKL003
        if let Some(matched) = PROMPT_INJECTION.find(&text) {
            findings.push(rules::make(
                "SKL003",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }

        // ---------------------------------------------------------- SKL004
        if let Some(matched) = SENSITIVE_PATH.find(&text) {
            findings.push(rules::make(
                "SKL004",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }

        // ---------------------------------------------------------- SKL005
        if let Some(offset) = first_hidden_unicode(&text) {
            findings.push(rules::make(
                "SKL005",
                display.clone(),
                line_at(&text, offset),
                "hidden or bidirectional Unicode character",
                None,
            ));
        }
    }

    (findings, scanned)
}

fn first_hidden_unicode(input: &str) -> Option<usize> {
    input.char_indices().find_map(|(offset, character)| {
        let hidden = matches!(
            character,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        );
        hidden.then_some(offset)
    })
}
