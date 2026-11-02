use crate::discovery;
use crate::finding::Finding;
use crate::rules;
use crate::util::{display_path, line_at, read_text};
use regex::Regex;
use std::path::PathBuf;
use std::sync::LazyLock;

static VECTOR_DB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:chroma|chromadb|pinecone|weaviate|qdrant|milvus|pgvector|faiss|vector[_-]?store|vector[_-]?db|embedding(?:s)?)\b",
    )
    .expect("valid vector db regex")
});

static NETWORK_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:https?://|host\s*[:=]|endpoint\s*[:=]|url\s*[:=]|server\s*[:=])")
        .expect("valid network endpoint regex")
});

static AUTH_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:api[_-]?key|token|password|passwd|auth|username|credentials|bearer)\b")
        .expect("valid auth regex")
});

static HTTP_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"http://[^\s"'<>]+"#).expect("valid http URL regex"));

static ALLOW_RESET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)allow[_-]?reset\s*[:=]\s*(?:true|yes|1)\b").expect("valid allow reset regex")
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
        if !VECTOR_DB.is_match(&text) {
            continue;
        }

        scanned += 1;
        let display = display_path(path);

        // ---------------------------------------------------------- RAG001
        if NETWORK_ENDPOINT.is_match(&text) && !AUTH_HINT.is_match(&text) {
            let evidence = VECTOR_DB
                .find(&text)
                .map(|matched| matched.as_str().to_string())
                .unwrap_or_else(|| "vector database".to_string());
            findings.push(rules::make(
                "RAG001",
                display.clone(),
                1,
                format!("{evidence} with unauthenticated network endpoint"),
                None,
            ));
        }

        // ---------------------------------------------------------- RAG002
        if let Some(matched) = HTTP_URL.find(&text) {
            let url = matched.as_str();
            if !url.contains("localhost") && !url.contains("127.0.0.1") && !url.contains("[::1]") {
                findings.push(rules::make(
                    "RAG002",
                    display.clone(),
                    line_at(&text, matched.start()),
                    url,
                    None,
                ));
            }
        }

        // ---------------------------------------------------------- RAG003
        if let Some(matched) = ALLOW_RESET.find(&text) {
            findings.push(rules::make(
                "RAG003",
                display.clone(),
                line_at(&text, matched.start()),
                matched.as_str(),
                None,
            ));
        }
    }

    (findings, scanned)
}
