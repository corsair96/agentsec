use std::path::Path;

/// Truncate a string to `max` characters, adding an ellipsis when needed.
pub fn truncate(input: &str, max: usize) -> String {
    let input = input.trim();
    if input.chars().count() <= max {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Number of lines before a byte offset (1-based).
pub fn line_at(text: &str, byte_offset: usize) -> usize {
    let offset = byte_offset.min(text.len());
    text[..offset].bytes().filter(|byte| *byte == b'\n').count() + 1
}

/// Line containing the first occurrence of `needle`.
pub fn line_of(text: &str, needle: &str) -> usize {
    text.find(needle)
        .map(|offset| line_at(text, offset))
        .unwrap_or(1)
}

/// Prefer a path relative to the current directory for display.
pub fn display_path(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(relative) = path.strip_prefix(&cwd) {
            let rendered = relative.to_string_lossy();
            if !rendered.is_empty() {
                return rendered.into_owned();
            }
        }
    }
    path.to_string_lossy().into_owned()
}

/// Read a text file, skipping files larger than 2 MiB and non-UTF-8 content.
pub fn read_text(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Mask a credential so it can be shown in reports safely.
pub fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.trim().chars().collect();
    if chars.len() <= 8 {
        return "***".to_string();
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().rev().take(2).rev().collect();
    format!("{head}…{tail}")
}

pub fn is_binary_extension(extension: &str) -> bool {
    matches!(
        extension,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "pdf"
            | "zip"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "7z"
            | "tar"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "class"
            | "jar"
            | "wasm"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "mp3"
            | "mp4"
            | "mov"
            | "avi"
            | "sqlite"
            | "db"
    )
}
