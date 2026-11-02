use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::scanners::secrets::secret_hits;
use crate::util::{display_path, line_at, line_of, read_text};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static REMOTE_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:(?:ba|z|fi)?sh|powershell|pwsh)\b[^\n]{0,80}?-(?:[a-z]*c)[a-z]*\b[^\n]{0,240}?(?:curl|wget|invoke-webrequest|iwr)|\b(?:curl|wget)\b[^|\n]{0,240}\|\s*(?:ba|z|fi)?sh\b"#,
    )
    .expect("valid remote shell regex")
});

static UNPINNED_EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[/\\])(?:npx|bunx|pnpm|yarn)$").expect("valid package runner regex")
});

static SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:~|\$home|\$\{home\})/(?:\.ssh|\.aws|\.gnupg|\.config)|/etc/(?:passwd|shadow)|(?:^|[/\\])\.env\b|id_(?:rsa|ed25519)|credentials",
    )
    .expect("valid sensitive path regex")
});

static POISON_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        (
            "instruction override",
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions",
        ),
        (
            "secret access instruction",
            r"(?i)(?:read|cat|open|exfiltrate|upload|send)[^\n]{0,60}(?:\.ssh|\.aws|\.env|/etc/passwd|credentials|api[_-]?key|token)",
        ),
        (
            "stealth instruction",
            r"(?i)do\s+not\s+(?:tell|inform|mention|reveal|alert)",
        ),
        (
            "consent bypass",
            r"(?i)without\s+(?:asking|confirmation|consent|approval)",
        ),
        (
            "pre-answer instruction",
            r"(?i)before\s+(?:answering|responding|any\s+response)",
        ),
        (
            "remote fetch instruction",
            r"(?i)(?:curl|wget)\s+https?://",
        ),
        ("system prompt reference", r"(?i)system\s+prompt"),
        ("priority markup", r"(?i)</?important>"),
    ]
    .into_iter()
    .map(|(label, pattern)| {
        (
            label,
            Regex::new(pattern).expect("valid tool poisoning regex"),
        )
    })
    .collect()
});

pub fn scan(files: &[PathBuf]) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for path in files {
        if !discovery::is_mcp_config(path) {
            continue;
        }
        let Some(text) = read_text(path) else {
            continue;
        };
        scanned += 1;

        let display = display_path(path);
        let client = client_for(path);
        let value = parse_json_lenient(&text);

        let Some(value) = value else {
            continue;
        };

        let Some(servers) = server_map(&value) else {
            continue;
        };

        for (name, server) in servers {
            scan_server(name, server, &text, &display, &client, &mut findings);
        }
    }

    (findings, scanned)
}

fn server_map(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    for key in ["mcpServers", "servers"] {
        if let Some(servers) = value.get(key).and_then(Value::as_object) {
            return Some(servers);
        }
    }
    value
        .get("mcp")
        .and_then(|mcp| mcp.get("servers"))
        .and_then(Value::as_object)
}

fn scan_server(
    name: &str,
    server: &Value,
    text: &str,
    display: &str,
    client: &Option<String>,
    findings: &mut Vec<Finding>,
) {
    let server_line = line_of(text, name);

    let command = server
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args: Vec<String> = server
        .get("args")
        .and_then(Value::as_array)
        .map(|args| {
            args.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let command_line = format!("{} {}", command, args.join(" ")).trim().to_string();

    // ---------------------------------------------------------- MCP003
    if REMOTE_SHELL.is_match(&command_line) {
        findings.push(rules::make(
            "MCP003",
            display,
            server_line,
            command_line.clone(),
            client.clone(),
        ));
    }

    // ---------------------------------------------------------- MCP005
    if !command.is_empty()
        && UNPINNED_EXEC.is_match(command)
        && args.iter().any(|arg| arg == "-y" || arg == "--yes")
        && !args.iter().any(|arg| is_pinned_package(arg))
    {
        findings.push(rules::make(
            "MCP005",
            display,
            server_line,
            command_line.clone(),
            client.clone(),
        ));
    }

    // ---------------------------------------------------------- MCP004
    let endpoint = ["url", "serverUrl", "endpoint"]
        .iter()
        .find_map(|key| server.get(*key).and_then(Value::as_str));
    if let Some(endpoint) = endpoint {
        if endpoint.starts_with("http://")
            && !endpoint.contains("localhost")
            && !endpoint.contains("127.0.0.1")
            && !endpoint.contains("[::1]")
        {
            findings.push(rules::make(
                "MCP004",
                display,
                line_of(text, endpoint),
                endpoint,
                client.clone(),
            ));
        }
    }

    // ---------------------------------------------------------- MCP001
    let mut secret_candidates: Vec<(String, String)> = Vec::new();
    if !command_line.is_empty() {
        secret_candidates.push(("command".to_string(), command_line.clone()));
    }
    if let Some(env) = server.get("env").and_then(Value::as_object) {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                secret_candidates.push((format!("env.{key}"), value.to_string()));
            }
        }
    }
    for (label, value) in &secret_candidates {
        if let Some(hit) = secret_hits(value, false).into_iter().next() {
            findings.push(rules::make(
                "MCP001",
                display,
                line_at(text, text.find(value.as_str()).unwrap_or(0)),
                format!("{label}: {} {}", hit.name, hit.masked),
                client.clone(),
            ));
        }
    }

    // ---------------------------------------------------------- MCP006
    let sensitive_source = format!(
        "{} {}",
        command_line,
        secret_candidates
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    if SENSITIVE_PATH.is_match(&sensitive_source) {
        let evidence = SENSITIVE_PATH
            .find(&sensitive_source)
            .map(|matched| matched.as_str().to_string())
            .unwrap_or_else(|| "sensitive path".to_string());
        findings.push(rules::make(
            "MCP006",
            display,
            line_of(text, &evidence),
            evidence,
            client.clone(),
        ));
    }

    // ---------------------------------------------------------- MCP002
    let mut descriptions = Vec::new();
    collect_key_strings(server, &["description", "instructions"], &mut descriptions);
    let mut seen = HashSet::new();
    for description in descriptions {
        if !seen.insert(description.clone()) {
            continue;
        }
        if let Some(label) = poison_label(&description) {
            findings.push(rules::make(
                "MCP002",
                display,
                line_of(text, &description),
                format!("{label}: {description}"),
                client.clone(),
            ));
            break;
        }
    }
}

fn is_pinned_package(argument: &str) -> bool {
    argument
        .rsplit('@')
        .next()
        .and_then(|version| version.chars().next())
        .map(|character| character.is_ascii_digit())
        .unwrap_or(false)
}

fn poison_label(description: &str) -> Option<&'static str> {
    if has_hidden_unicode(description) {
        return Some("hidden unicode");
    }
    POISON_PATTERNS
        .iter()
        .find(|(_, regex)| regex.is_match(description))
        .map(|(label, _)| *label)
}

fn has_hidden_unicode(input: &str) -> bool {
    input.chars().any(|character| {
        matches!(
            character,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
    })
}

fn collect_key_strings(value: &Value, keys: &[&str], out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if keys.contains(&key.as_str()) {
                    if let Some(text) = value.as_str() {
                        out.push(text.to_string());
                    }
                }
                collect_key_strings(value, keys, out);
            }
        }
        Value::Array(array) => {
            for value in array {
                collect_key_strings(value, keys, out);
            }
        }
        _ => {}
    }
}

fn client_for(path: &Path) -> Option<String> {
    let rendered = path.to_string_lossy().to_ascii_lowercase();
    if rendered.contains("/.cursor/") {
        Some("cursor".to_string())
    } else if rendered.contains("/.vscode/") {
        Some("vscode".to_string())
    } else if rendered.contains("/.gemini/") {
        Some("gemini".to_string())
    } else if rendered.contains("claude") || rendered.contains("/.claude/") {
        Some("claude".to_string())
    } else if rendered.contains("/.codex/") {
        Some("codex".to_string())
    } else {
        None
    }
}

/// Parse strict JSON first, then retry after stripping // and /* */ comments
/// plus trailing commas (mcp.json files are frequently JSONC).
fn parse_json_lenient(text: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str(text) {
        return Some(value);
    }
    let stripped = strip_json_comments(text);
    let without_trailing_commas = Regex::new(r",(\s*[}\]])").expect("valid trailing comma regex");
    let cleaned = without_trailing_commas.replace_all(&stripped, "$1");
    serde_json::from_str(&cleaned).ok()
}

fn strip_json_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while index < bytes.len() {
        let byte = bytes[index];

        if in_string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if byte == b'"' {
            in_string = true;
            out.push(byte);
            index += 1;
            continue;
        }

        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }

        if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
            continue;
        }

        out.push(byte);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}
