use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
    ".idea",
    ".gradle",
];

fn is_ignored_dir(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return false;
    }
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    IGNORED_DIRS.iter().any(|ignored| *ignored == name)
}

/// Collect candidate files from the given root, plus well-known home
/// locations when `auto` is enabled.
pub fn collect(root: &Path, auto: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();

    if root.is_file() {
        files.push(root.to_path_buf());
    } else if root.is_dir() {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| !is_ignored_dir(entry))
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let extension = entry
                .path()
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();

            if crate::util::is_binary_extension(&extension) {
                continue;
            }

            files.push(entry.into_path());
        }
    }

    if auto {
        for path in auto_paths() {
            if path.is_file() {
                files.push(path);
            }
        }
    }

    deduplicate(files)
}

fn deduplicate(files: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for file in files {
        let key = file.canonicalize().unwrap_or_else(|_| file.clone());
        if seen.insert(key) {
            out.push(file);
        }
    }
    out
}

fn auto_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = dirs::home_dir() {
        for relative in [
            ".cursor/mcp.json",
            ".claude/mcp.json",
            ".claude.json",
            ".claude/claude_desktop_config.json",
            ".config/claude/claude_desktop_config.json",
            ".config/Claude/claude_desktop_config.json",
            ".gemini/mcp.json",
            ".gemini/settings.json",
            ".codex/config.toml",
        ] {
            paths.push(home.join(relative));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        for relative in [
            ".mcp.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
            ".claude/settings.json",
        ] {
            paths.push(cwd.join(relative));
        }
    }

    paths
}

/// Heuristic: is this file an MCP client/server configuration?
pub fn is_mcp_config(path: &Path) -> bool {
    if is_skill(path) {
        return false;
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rendered = path.to_string_lossy().to_ascii_lowercase();

    matches!(
        name.as_str(),
        "mcp.json" | ".mcp.json" | "claude_desktop_config.json" | ".claude.json"
    ) || (name == "settings.json"
        && (rendered.contains("/.claude/") || rendered.contains("/.gemini/")))
        || rendered.contains("/.cursor/")
        || rendered.contains("/.vscode/")
}

/// Heuristic: is this file a skill definition?
pub fn is_skill(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rendered = path.to_string_lossy().to_ascii_lowercase();

    name == "skill.md"
        || name.ends_with(".skill.md")
        || rendered.contains("/.claude/skills/")
        || rendered.contains("/.codex/skills/")
}

/// Heuristic: is this file a dotenv or CI secret-bearing file?
pub fn is_env_or_ci(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let rendered = path.to_string_lossy().to_ascii_lowercase();

    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || rendered.contains("/.github/workflows/")
        || name == ".npmrc"
        || name == ".pypirc"
        || name == "credentials"
}

pub fn is_code(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "py" | "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs"
    )
}

pub fn is_config(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "yaml" | "yml" | "json" | "toml" | "ini" | "conf"
    )
}
