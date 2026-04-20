use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

static VID_PID_REGEX: OnceLock<Regex> = OnceLock::new();
static EXPLORER_URI_REGEX: OnceLock<Regex> = OnceLock::new();
static WINDOWS_PATH_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn extract_vid_pid(device_id: &str) -> Option<(String, String)> {
    let regex = VID_PID_REGEX.get_or_init(|| {
        Regex::new(r"(?i)VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})").expect("VID/PID regex is valid")
    });
    let captures = regex.captures(device_id)?;
    Some((captures[1].to_uppercase(), captures[2].to_uppercase()))
}

pub fn normalize_explorer_uri(line: &str) -> Option<PathBuf> {
    let trimmed = line.trim();
    let regex = EXPLORER_URI_REGEX.get_or_init(|| {
        Regex::new(r#"(?i)file:///([A-Z]:/[^"'<>\s]+?\.(?:exe|bat|jar|vbs|py|ps1))\b"#)
            .expect("explorer file URI regex is valid")
    });
    let uri = regex.captures(trimmed)?.get(1)?.as_str();
    let decoded = percent_decode(uri);
    let normalized = decoded.replace("\\20", "\\").replace('/', "\\");

    if normalized.contains(":\\") {
        Some(PathBuf::from(normalized))
    } else {
        None
    }
}

fn percent_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let raw = input.as_bytes();
    let mut index = 0usize;

    while index < raw.len() {
        if raw[index] == b'%'
            && index + 2 < raw.len()
            && let (Some(high), Some(low)) = (from_hex(raw[index + 1]), from_hex(raw[index + 2]))
        {
            bytes.push((high << 4) | low);
            index += 3;
            continue;
        }

        bytes.push(raw[index]);
        index += 1;
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

fn from_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn extract_windows_paths(line: &str) -> Vec<String> {
    let regex = WINDOWS_PATH_REGEX.get_or_init(|| {
        Regex::new(r#"(?i)([A-Z]:\\[^"'<>\r\n]+?\.(?:exe|dll|bat|jar|vbs|ps1|py))"#)
            .expect("Windows path regex is valid")
    });

    regex
        .captures_iter(line)
        .filter_map(|captures| {
            captures
                .get(1)
                .map(|item| item.as_str().trim_matches('"').to_string())
        })
        .collect()
}

pub fn detect_special_extension_fragment(previous: &str, current: &str) -> bool {
    let normalized_previous = previous.trim();
    let normalized_current = current.trim().to_ascii_lowercase();
    normalized_previous.ends_with('\\')
        && matches!(
            normalized_current.as_str(),
            ".exe" | ".dll" | ".bat" | ".jar" | ".vbs" | ".ps1" | ".py"
        )
}

pub fn contains_non_ascii(line: &str) -> bool {
    !line.is_ascii()
}
