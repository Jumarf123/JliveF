use std::path::Path;

use rayon::prelude::*;

use crate::bypass_scan::context::{ScanContext, ScanProfile};
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    collect_candidate_files, path_display, prefetch_file_names_by_prefixes, query_event_records,
    read_file_all, truncate_text,
};

const MEDIA_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp", "bmp"];
const STEGO_TOOL_PREFIXES: &[&str] = &[
    "OPENSTEGO.EXE-",
    "STEGHIDE.EXE-",
    "STEGSEEK.EXE-",
    "SILENTEYE.EXE-",
    "ZSTEG.EXE-",
    "OUTGUESS.EXE-",
    "BINWALK.EXE-",
];

pub fn run(ctx: &ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        10,
        "bypass10_stego",
        "Appended payload / polyglot hiding",
        "No high-confidence stego/polyglot evidence found.",
    );

    let max_files = match ctx.profile {
        ScanProfile::Quick => 100,
        ScanProfile::Deep => 1800,
    };

    let candidates = collect_candidate_files(ctx, MEDIA_EXTS, Some(max_files));

    let structure_hits = candidates
        .par_iter()
        .filter_map(|file| {
            let data = read_file_all(file)?;
            if data.len() > 48 * 1024 * 1024 {
                return None;
            }
            analyze_file(file, &data)
        })
        .collect::<Vec<_>>();

    let tool_hits = collect_tool_hits();

    if !structure_hits.is_empty() && !tool_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected structural polyglot payload markers correlated with stego/tool execution traces."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "File structure scan".to_string(),
            summary: format!("{} strong structural hit(s)", structure_hits.len()),
            details: structure_hits
                .iter()
                .take(60)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
        result.evidence.push(EvidenceItem {
            source: "Tool execution telemetry (Prefetch/4688/4104)".to_string(),
            summary: format!("{} stego-tool trace(s)", tool_hits.len()),
            details: tool_hits
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    } else if !structure_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Structural appended payload markers found, but no direct stego-tool execution traces."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "File structure scan".to_string(),
            summary: format!("{} structural hit(s)", structure_hits.len()),
            details: structure_hits
                .iter()
                .take(60)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    } else if !tool_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Stego-related tool execution traces found without structural embedded payload markers."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Tool execution telemetry (Prefetch/4688/4104)".to_string(),
            summary: format!("{} stego-tool trace(s)", tool_hits.len()),
            details: tool_hits
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    logger.log(
        "bypass10_stego",
        "info",
        "stego scan complete",
        serde_json::json!({
            "candidates": candidates.len(),
            "structure_hits": structure_hits.len(),
            "tool_hits": tool_hits.len(),
        }),
    );

    result
}

fn collect_tool_hits() -> Vec<String> {
    let mut out = Vec::new();

    for pf in prefetch_file_names_by_prefixes(STEGO_TOOL_PREFIXES) {
        out.push(format!("Prefetch: {pf}"));
    }

    let ps_events = query_event_records("Microsoft-Windows-PowerShell/Operational", &[4104], 200);
    let sec_events = query_event_records("Security", &[4688], 260);

    for ev in ps_events.into_iter().chain(sec_events.into_iter()) {
        let text = format!("{} {}", ev.message, ev.raw_xml).to_lowercase();
        if text.contains("openstego")
            || text.contains("steghide")
            || text.contains("stegseek")
            || text.contains("silenteye")
            || text.contains("outguess")
            || text.contains("zsteg")
            || text.contains("invoke-psimage")
            || text.contains("binwalk")
        {
            out.push(format!(
                "{} | Event {} | {}",
                ev.time_created,
                ev.event_id,
                truncate_text(&ev.message, 220)
            ));
        }
    }

    out
}

fn analyze_file(path: &Path, data: &[u8]) -> Option<String> {
    if data.len() < 256 {
        return None;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let eof = match ext.as_str() {
        "jpg" | "jpeg" => find_last(data, &[0xFF, 0xD9]).map(|p| p + 2),
        "png" => find_last(data, &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]).map(|p| p + 8),
        "gif" => data.iter().rposition(|b| *b == 0x3B).map(|p| p + 1),
        "bmp" | "webp" => None,
        _ => None,
    }?;

    if eof >= data.len() {
        return None;
    }

    let trailing = &data[eof..];
    if trailing.len() < 2048 {
        return None;
    }

    let (kind, rel_offset) = detect_tail_payload(trailing)?;
    Some(format!(
        "{} | trailing={} bytes | payload={} at +{}",
        path_display(path),
        trailing.len(),
        kind,
        rel_offset
    ))
}

fn detect_tail_payload(trailing: &[u8]) -> Option<(&'static str, usize)> {
    if let Some(pos) = find_first(trailing, b"PK\x03\x04") {
        if pos <= 2048 && has_zip_eocd(&trailing[pos..]) {
            return Some(("zip", pos));
        }
    }

    if let Some(pos) = find_first(trailing, b"Rar!\x1A\x07\x00") {
        if pos <= 1024 {
            return Some(("rar", pos));
        }
    }

    if let Some(pos) = find_first(trailing, b"Rar!\x1A\x07\x01\x00") {
        if pos <= 1024 {
            return Some(("rar", pos));
        }
    }

    if let Some(pos) = find_first(trailing, b"7z\xBC\xAF\x27\x1C") {
        if pos <= 1024 {
            return Some(("7z", pos));
        }
    }

    if let Some(pos) = find_first(trailing, b"MZ") {
        if pos <= 2048 && is_valid_pe(&trailing[pos..]) {
            return Some(("pe", pos));
        }
    }

    None
}

fn has_zip_eocd(data: &[u8]) -> bool {
    find_last(data, b"PK\x05\x06").is_some()
}

fn is_valid_pe(data: &[u8]) -> bool {
    if data.len() < 0x44 || &data[0..2] != b"MZ" {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew > 0x1000 || e_lfanew + 4 > data.len() {
        return false;
    }

    &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::{analyze_file, is_valid_pe};
    use std::path::Path;

    #[test]
    fn random_mz_without_pe_not_valid() {
        let mut data = vec![0u8; 3000];
        data[0] = b'M';
        data[1] = b'Z';
        assert!(!is_valid_pe(&data));
    }

    #[test]
    fn jpeg_with_small_tail_not_hit() {
        let mut bytes = vec![0xFF, 0xD8, 0x11, 0x22, 0xFF, 0xD9];
        bytes.extend_from_slice(&[0u8; 700]);
        bytes.extend_from_slice(b"PK\x03\x04abc");
        assert!(analyze_file(Path::new("x.jpg"), &bytes).is_none());
    }
}
