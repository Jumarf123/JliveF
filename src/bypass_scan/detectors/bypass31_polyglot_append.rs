use std::path::Path;

use rayon::prelude::*;

use crate::bypass_scan::context::ScanContext;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, collect_candidate_files, path_display, query_event_records, read_file_all,
    truncate_text,
};

pub fn run(ctx: &ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        31,
        "bypass31_polyglot_append",
        "Polyglot/append archive payload",
        "No high-confidence appended payload after file EOF marker found.",
    );

    let max_candidates = match ctx.profile {
        crate::bypass_scan::context::ScanProfile::Quick => 140,
        crate::bypass_scan::context::ScanProfile::Deep => 2400,
    };

    let candidates = collect_candidate_files(
        ctx,
        &["jpg", "jpeg", "png", "gif", "pdf"],
        Some(max_candidates),
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_polyglot_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let findings = candidates
        .par_iter()
        .filter_map(|path| {
            let data = read_file_all(path)?;
            if data.len() > 32 * 1024 * 1024 {
                return None;
            }
            detect_appended_payload(path, &data)
        })
        .take_any_while(|_| true)
        .collect::<Vec<_>>();

    if findings.len() >= 2 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected multiple files with valid EOF marker followed by embedded archive/PE signatures."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "File structure analysis".to_string(),
            summary: format!("{} suspicious polyglot/append file(s)", findings.len()),
            details: findings
                .iter()
                .take(80)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
        if !command_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!(
                    "{} polyglot construction command trace(s)",
                    command_hits.len()
                ),
                details: command_hits.join("; "),
            });
        }
        result.recommendations.push(
            "Preserve original files and verify payload extraction in an isolated forensic environment."
                .to_string(),
        );
    } else if findings.len() == 1 {
        result.status = DetectionStatus::Detected;
        result.confidence = if !command_hits.is_empty() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        result.summary = if !command_hits.is_empty() {
            "Single polyglot-like file found with matching build/append command telemetry."
                .to_string()
        } else {
            "Single strong polyglot-like file found; validate origin and related command history."
                .to_string()
        };
        result.evidence.push(EvidenceItem {
            source: "File structure analysis".to_string(),
            summary: "1 suspicious polyglot/append file".to_string(),
            details: findings[0].clone(),
        });
        if !command_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!(
                    "{} polyglot construction command trace(s)",
                    command_hits.len()
                ),
                details: command_hits.join("; "),
            });
        }
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Polyglot/append construction commands detected, but suspicious target file is not currently recoverable in scan scope."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!(
                "{} polyglot construction command trace(s)",
                command_hits.len()
            ),
            details: command_hits.join("; "),
        });
    }

    logger.log(
        "bypass31_polyglot_append",
        "info",
        "polyglot checks complete",
        serde_json::json!({
            "candidates": candidates.len(),
            "findings": findings.len(),
            "command_hits": command_hits.len(),
        }),
    );

    result
}

fn detect_appended_payload(path: &Path, data: &[u8]) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    let eof = match ext.as_str() {
        "jpg" | "jpeg" => find_last_sequence(data, &[0xFF, 0xD9]).map(|p| p + 2),
        "png" => find_last_sequence(data, &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
            .map(|p| p + 8),
        "gif" => data.iter().rposition(|b| *b == 0x3B).map(|p| p + 1),
        "pdf" => find_last_sequence(data, b"%%EOF").map(|p| p + 5),
        _ => None,
    }?;

    if eof + 2048 >= data.len() {
        return None;
    }

    let tail = &data[eof..];
    let (sig_name, sig_offset) = find_embedded_signature(tail)?;

    Some(format!(
        "{} | trailing={} bytes | sig={} at +{}",
        path_display(path),
        data.len() - eof,
        sig_name,
        sig_offset
    ))
}

fn find_embedded_signature(data: &[u8]) -> Option<(&'static str, usize)> {
    if let Some(pos) = find_sequence(data, b"PK\x03\x04") {
        if pos <= 2048 && find_last_sequence(data, b"PK\x05\x06").is_some() {
            return Some(("zip", pos));
        }
    }

    if let Some(pos) = find_sequence(data, b"Rar!\x1A\x07\x00") {
        if pos <= 1024 {
            return Some(("rar", pos));
        }
    }
    if let Some(pos) = find_sequence(data, b"Rar!\x1A\x07\x01\x00") {
        if pos <= 1024 {
            return Some(("rar", pos));
        }
    }

    if let Some(pos) = find_sequence(data, b"7z\xBC\xAF\x27\x1C") {
        if pos <= 1024 {
            return Some(("7z", pos));
        }
    }

    if let Some(pos) = find_sequence(data, b"MZ") {
        if pos <= 2048 && is_valid_pe(&data[pos..]) {
            return Some(("pe", pos));
        }
    }

    None
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

fn find_last_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn collect_polyglot_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_polyglot_build_command(&normalized) {
                continue;
            }
            hits.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220)
            ));
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

fn looks_like_polyglot_build_command(text: &str) -> bool {
    let normalized = text.to_lowercase();

    let copy_b_concat = normalized.contains("copy /b") && normalized.contains('+');
    let append_redirect = (normalized.contains(">>") || normalized.contains("add-content"))
        && (normalized.contains(".jpg")
            || normalized.contains(".jpeg")
            || normalized.contains(".png")
            || normalized.contains(".gif")
            || normalized.contains(".pdf"));
    let archive_into_media =
        (normalized.contains("zip") || normalized.contains("rar") || normalized.contains("7z"))
            && (normalized.contains(".jpg")
                || normalized.contains(".jpeg")
                || normalized.contains(".png")
                || normalized.contains(".gif")
                || normalized.contains(".pdf"))
            && (normalized.contains("copy")
                || normalized.contains("cat")
                || normalized.contains("type"));

    copy_b_concat || append_redirect || archive_into_media
}

#[cfg(test)]
mod tests {
    use super::{detect_appended_payload, looks_like_polyglot_build_command};
    use std::path::Path;

    #[test]
    fn command_matcher_detects_copy_b_concat() {
        assert!(looks_like_polyglot_build_command(
            "cmd /c copy /b image.jpg+payload.zip out.jpg"
        ));
        assert!(!looks_like_polyglot_build_command(
            "cmd /c copy image.jpg out.jpg"
        ));
    }

    #[test]
    fn detect_appended_payload_finds_zip_after_jpeg_eof() {
        let mut data = vec![0xFF, 0xD8, 0x00, 0x11, 0x22, 0xFF, 0xD9];
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[0; 3000]);
        data.extend_from_slice(b"PK\x05\x06");
        let finding = detect_appended_payload(Path::new("sample.jpg"), &data);
        assert!(finding.is_some());
    }
}
