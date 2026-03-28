use crate::bypass_scan::context::{ScanContext, ScanProfile};
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{collect_candidate_files, prefetch_dir, read_file_head};
use std::fs;

const NON_EXECUTABLE_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "txt", "log", "pdf", "mp3", "mp4", "dat",
];

pub fn run(ctx: &ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        12,
        "bypass12_extension_spoof",
        "Extension spoofing of executable payloads",
        "No high-confidence extension spoofing indicators found.",
    );

    let prefetch_hits = find_prefetch_extension_hits();
    let file_hits = find_disguised_files(ctx);

    if !prefetch_hits.is_empty() && !file_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected executable behavior under non-executable extensions.".to_string();

        if !prefetch_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: r"C:\Windows\Prefetch".to_string(),
                summary: format!(
                    "{} suspicious prefetch executable names",
                    prefetch_hits.len()
                ),
                details: prefetch_hits
                    .iter()
                    .take(30)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        if !file_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "File header scan".to_string(),
                summary: format!("{} disguised payload file(s)", file_hits.len()),
                details: file_hits
                    .iter()
                    .take(40)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        result.recommendations.push(
            "Quarantine suspicious files and correlate with process command-line telemetry."
                .to_string(),
        );
    } else if !file_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Disguised file headers found under non-executable extensions. Validate provenance."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "File header scan".to_string(),
            summary: format!("{} disguised payload file(s)", file_hits.len()),
            details: file_hits
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    } else if !prefetch_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Suspicious prefetch executable naming found without matching disguised files."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!(
                "{} suspicious prefetch executable names",
                prefetch_hits.len()
            ),
            details: prefetch_hits
                .iter()
                .take(30)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    logger.log(
        "bypass12_extension_spoof",
        "info",
        "extension spoof checks complete",
        serde_json::json!({
            "prefetch_hits": prefetch_hits.len(),
            "file_hits": file_hits.len(),
        }),
    );

    result
}

fn find_prefetch_extension_hits() -> Vec<String> {
    let mut hits = Vec::new();
    let dir = prefetch_dir();

    let Ok(entries) = fs::read_dir(dir) else {
        return hits;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pf") {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let Some(exe_part) = name.split('-').next() else {
            continue;
        };

        let ext = exe_part
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_lowercase();
        if ext.is_empty() {
            continue;
        }

        if NON_EXECUTABLE_EXTS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&ext))
        {
            hits.push(name);
        }
    }

    hits
}

fn find_disguised_files(ctx: &ScanContext) -> Vec<String> {
    let max_files = match ctx.profile {
        ScanProfile::Quick => 140,
        ScanProfile::Deep => 420,
    };
    let files = collect_candidate_files(ctx, NON_EXECUTABLE_EXTS, Some(max_files));

    let mut hits = Vec::new();
    for file in files {
        if let Some(head) = read_file_head(&file, 8) {
            if head.starts_with(b"MZ") {
                hits.push(format!("{} (MZ header)", file.display()));
            } else if head.starts_with(b"PK\x03\x04") {
                let ext = file
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or_default()
                    .to_lowercase();
                if ["png", "jpg", "jpeg", "gif", "bmp", "txt", "mp3", "mp4"].contains(&ext.as_str())
                {
                    hits.push(format!("{} (ZIP/JAR header)", file.display()));
                }
            }
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::NON_EXECUTABLE_EXTS;

    #[test]
    fn extension_list_contains_png() {
        assert!(NON_EXECUTABLE_EXTS.contains(&"png"));
    }
}
