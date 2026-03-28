use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, query_ntfs_volume_metadata,
    query_usn_journal_states, truncate_text,
};

const USN_DELETE_COMMAND_NEEDLES: &[&str] = &[
    "fsutil usn deletejournal",
    "fsutil.exe usn deletejournal",
    "usn deletejournal /d",
    "deletejournal /d",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        15,
        "bypass15_usn_clear",
        "USN journal clearing",
        "No high-confidence USN journal clear evidence found.",
    );

    let fsutil_prefetch = prefetch_file_names_by_prefixes(&["FSUTIL.EXE-"]);

    let mut usn_events = query_event_records("Application", &[3079, 501, 98], 220);
    usn_events.extend(query_event_records("System", &[501, 98], 160));

    let mut high_hits = Vec::new();
    let mut medium_hits = Vec::new();
    for event in usn_events {
        if should_skip_noise(&event) {
            continue;
        }

        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if is_high_confidence_usn_event(event.event_id, &normalized) {
            high_hits.push(format_event_hit(&event));
        } else if is_medium_confidence_usn_event(event.event_id, &normalized) {
            medium_hits.push(format_event_hit(&event));
        }
    }

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        300,
    );
    let sec_events = query_event_records("Security", &[4688], 360);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 300);
    let command_hits = collect_usn_delete_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let usn_states = query_usn_journal_states();
    let ntfs_metadata = query_ntfs_volume_metadata();
    let missing_volumes = usn_states
        .iter()
        .filter(|s| s.missing && !s.access_denied)
        .collect::<Vec<_>>();
    let denied_volumes = usn_states
        .iter()
        .filter(|s| s.access_denied)
        .collect::<Vec<_>>();

    if !high_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected direct event traces of USN journal deletion.".to_string();
        result.evidence.push(EvidenceItem {
            source: "Application/System Event Log".to_string(),
            summary: format!("{} high-confidence event hit(s)", high_hits.len()),
            details: high_hits.join("; "),
        });

        if !command_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!(
                    "{} fsutil deletejournal command trace(s)",
                    command_hits.len()
                ),
                details: command_hits.join("; "),
            });
        }
    } else if !command_hits.is_empty() && !missing_volumes.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "USN deletejournal command traces correlate with missing USN journal state."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!(
                "{} fsutil deletejournal command trace(s)",
                command_hits.len()
            ),
            details: command_hits.join("; "),
        });
    } else if !command_hits.is_empty() || !medium_hits.is_empty() {
        let weak_signal_count = (if !command_hits.is_empty() { 1 } else { 0 })
            + (if !medium_hits.is_empty() { 1 } else { 0 })
            + (if !missing_volumes.is_empty() { 1 } else { 0 })
            + (if !fsutil_prefetch.is_empty() { 1 } else { 0 });

        if weak_signal_count >= 2 {
            result.status = DetectionStatus::Detected;
            result.confidence = Confidence::Medium;
            result.summary =
                "Multiple USN-related indicators found; contextual validation is required."
                    .to_string();
        } else {
            result.status = DetectionStatus::Detected;
            result.confidence = Confidence::Low;
            result.summary =
                "Single weak USN signal found; insufficient for confident bypass attribution."
                    .to_string();
        }

        if !medium_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Application/System Event Log".to_string(),
                summary: format!("{} medium-confidence event hit(s)", medium_hits.len()),
                details: medium_hits.join("; "),
            });
        }
        if !command_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!(
                    "{} fsutil deletejournal command trace(s)",
                    command_hits.len()
                ),
                details: command_hits.join("; "),
            });
        }
    } else if !missing_volumes.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "USN journal is missing on one or more volumes without direct delete evidence."
                .to_string();
    }

    if !fsutil_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} FSUTIL prefetch file(s)", fsutil_prefetch.len()),
            details: fsutil_prefetch.join("; "),
        });
    }

    if !usn_states.is_empty() {
        let state_lines = usn_states
            .iter()
            .map(|state| {
                let state_text = if state.access_denied {
                    "access_denied"
                } else if state.missing {
                    "missing"
                } else if state.available {
                    "available"
                } else {
                    "unknown"
                };
                format!("{} | state={}", state.volume, state_text)
            })
            .collect::<Vec<_>>();
        result.evidence.push(EvidenceItem {
            source: "fsutil usn queryjournal".to_string(),
            summary: format!(
                "{} volume(s) checked, missing={}, access_denied={}",
                usn_states.len(),
                missing_volumes.len(),
                denied_volumes.len()
            ),
            details: state_lines.join("; "),
        });
    }

    if !ntfs_metadata.is_empty() {
        let metadata_lines = ntfs_metadata
            .iter()
            .map(|meta| {
                format!(
                    "{} | NTFS={} LFS={} MFT_valid_len={} MFT_LCN={} MFTMirr_LCN={} FRS={} err={}",
                    meta.volume,
                    meta.ntfs_version
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.lfs_version
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.mft_valid_data_length
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.mft_start_lcn
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.mft_mirror_start_lcn
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.bytes_per_file_record_segment
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    meta.error.clone().unwrap_or_else(|| "none".to_string()),
                )
            })
            .collect::<Vec<_>>();
        result.evidence.push(EvidenceItem {
            source: "fsutil fsinfo ntfsinfo (MFT metadata)".to_string(),
            summary: format!("{} volume(s) NTFS metadata collected", ntfs_metadata.len()),
            details: metadata_lines.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate USN signals with Event Log clear operations and execution evidence (fsutil/powershell).".to_string(),
        );
        result.recommendations.push(
            "If centralized logging is enabled, verify whether USN-clear related process events exist there."
                .to_string(),
        );
    }

    logger.log(
        "bypass15_usn_clear",
        "info",
        "usn checks complete",
        serde_json::json!({
            "high_hits": high_hits.len(),
            "medium_hits": medium_hits.len(),
            "command_hits": command_hits.len(),
            "prefetch_hits": fsutil_prefetch.len(),
            "volume_count": usn_states.len(),
            "ntfs_metadata_count": ntfs_metadata.len(),
            "missing_volumes": missing_volumes.len(),
            "access_denied_volumes": denied_volumes.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn format_event_hit(event: &EventRecord) -> String {
    format!(
        "{} | Event {} | {} | {}",
        event.time_created,
        event.event_id,
        event.provider,
        truncate_text(&event.message, 220),
    )
}

fn should_skip_noise(event: &EventRecord) -> bool {
    let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
    normalized.contains("searchindexer")
}

fn is_high_confidence_usn_event(event_id: u32, text_lower: &str) -> bool {
    let normalized = text_lower.to_lowercase();
    normalized.contains("fsctl_delete_usn_journal")
        || normalized.contains("usn journal deleted")
        || normalized.contains("delete usn journal")
        || (event_id == 3079
            && (normalized.contains("usn")
                || normalized.contains("journal")
                || normalized.contains("delete")))
}

fn is_medium_confidence_usn_event(event_id: u32, text_lower: &str) -> bool {
    if is_high_confidence_usn_event(event_id, text_lower) {
        return false;
    }

    let normalized = text_lower.to_lowercase();
    (event_id == 501 || event_id == 98)
        && (normalized.contains("usn")
            || normalized.contains("journal")
            || normalized.contains("fsutil"))
}

fn collect_usn_delete_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_usn_delete_command(&normalized) {
                continue;
            }

            hits.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn looks_like_usn_delete_command(text_lower: &str) -> bool {
    let normalized = text_lower.to_lowercase();
    USN_DELETE_COMMAND_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        is_high_confidence_usn_event, is_medium_confidence_usn_event, looks_like_usn_delete_command,
    };

    #[test]
    fn usn_command_pattern_detects_deletejournal() {
        assert!(looks_like_usn_delete_command(
            "cmd /c fsutil usn deletejournal /d c:"
        ));
        assert!(!looks_like_usn_delete_command("fsutil usn queryjournal c:"));
    }

    #[test]
    fn usn_event_scoring_prefers_high_over_medium() {
        let text = "The FSCTL_DELETE_USN_JOURNAL operation completed";
        assert!(is_high_confidence_usn_event(3079, text));
        assert!(!is_medium_confidence_usn_event(3079, text));
        assert!(is_medium_confidence_usn_event(
            501,
            "fsutil touched usn journal"
        ));
    }
}
