use std::fs;

use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, get_file_attributes, prefetch_dir, query_event_records,
    query_ntfs_volume_metadata, query_usn_journal_states, truncate_text,
};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        13,
        "bypass13_prefetch_attrib",
        "Prefetch attribute manipulation",
        "No suspicious hidden/read-only/system attributes found on Prefetch .pf files.",
    );

    let dir = prefetch_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        result.status = DetectionStatus::Error;
        result.summary = format!("Failed to read {}", dir.display());
        result.error = Some("prefetch read_dir failed".to_string());
        return result;
    };

    let mut suspicious = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pf") {
            continue;
        }

        let Some(attrs) = get_file_attributes(&path) else {
            continue;
        };

        let mut flags = Vec::new();
        if attrs & FILE_ATTRIBUTE_READONLY.0 != 0 {
            flags.push("READONLY");
        }
        if attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0 {
            flags.push("HIDDEN");
        }
        if attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0 {
            flags.push("SYSTEM");
        }

        if !flags.is_empty() {
            suspicious.push(format!("{} [{}]", path.display(), flags.join(",")));
        }
    }

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_prefetch_attrib_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let usn_states = query_usn_journal_states();
    let ntfs_meta = query_ntfs_volume_metadata();

    if !suspicious.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Prefetch attribute anomalies correlate with explicit attrib tamper commands."
                .to_string();
    } else if !suspicious.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Prefetch files with anti-forensic attributes detected.".to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Prefetch attrib manipulation commands detected without current attribute residue."
                .to_string();
    }

    if !suspicious.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} suspicious .pf attribute entries", suspicious.len()),
            details: suspicious
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} prefetch attrib command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !usn_states.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "USN journal context".to_string(),
            summary: format!("{} volume(s) checked", usn_states.len()),
            details: usn_states
                .iter()
                .map(|s| {
                    let state = if s.access_denied {
                        "access_denied"
                    } else if s.missing {
                        "missing"
                    } else if s.available {
                        "available"
                    } else {
                        "unknown"
                    };
                    format!("{} | state={}", s.volume, state)
                })
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !ntfs_meta.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "NTFS metadata context".to_string(),
            summary: format!("{} volume(s) snapshot", ntfs_meta.len()),
            details: ntfs_meta
                .iter()
                .map(|m| {
                    format!(
                        "{} | ntfs={} lfs={} mft_lcn={} mftmirr_lcn={}",
                        m.volume,
                        m.ntfs_version
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        m.lfs_version
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        m.mft_start_lcn
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        m.mft_mirror_start_lcn
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Remove tampered attributes and preserve timeline before any cleanup action."
                .to_string(),
        );
    }

    logger.log(
        "bypass13_prefetch_attrib",
        "info",
        "prefetch attributes checked",
        serde_json::json!({
            "suspicious": suspicious.len(),
            "command_hits": command_hits.len(),
            "usn_volumes": usn_states.len(),
            "ntfs_volumes": ntfs_meta.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_prefetch_attrib_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_prefetch_attrib_command(&normalized) {
                continue;
            }
            let image =
                crate::bypass_scan::utils::extract_event_data_value(&event.raw_xml, "Image")
                    .or_else(|| {
                        crate::bypass_scan::utils::extract_event_data_value(
                            &event.raw_xml,
                            "NewProcessName",
                        )
                    })
                    .or_else(|| {
                        crate::bypass_scan::utils::extract_event_data_value(
                            &event.raw_xml,
                            "ProcessName",
                        )
                    })
                    .unwrap_or_else(|| "unknown_process".to_string());
            let cmd =
                crate::bypass_scan::utils::extract_event_data_value(&event.raw_xml, "CommandLine")
                    .or_else(|| {
                        crate::bypass_scan::utils::extract_event_data_value(
                            &event.raw_xml,
                            "ScriptBlockText",
                        )
                    })
                    .unwrap_or_else(|| event.message.clone());
            out.push(format!(
                "{} | {} Event {} | process={} | cmd={}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&image, 90),
                truncate_text(&cmd.replace('\n', " "), 170),
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_prefetch_attrib_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target_prefetch =
        normalized.contains("\\windows\\prefetch") || normalized.contains("c:\\windows\\prefetch");
    let target_pf = normalized.contains(".pf") || normalized.contains("*");

    let attrib_mutation = normalized.contains("attrib")
        && (normalized.contains("+r")
            || normalized.contains("+h")
            || normalized.contains("+s")
            || normalized.contains(" -r ")
            || normalized.contains(" -h ")
            || normalized.contains(" -s "));

    target_prefetch && target_pf && attrib_mutation
}

#[cfg(test)]
mod tests {
    use super::looks_like_prefetch_attrib_command;

    #[test]
    fn prefetch_attrib_matcher_detects_prefetch_specific_attrib_commands() {
        assert!(looks_like_prefetch_attrib_command(
            "attrib +r +h C:\\Windows\\Prefetch\\*.pf"
        ));
        assert!(looks_like_prefetch_attrib_command(
            "cmd /c attrib +s C:\\Windows\\Prefetch\\ABC.PF"
        ));
        assert!(!looks_like_prefetch_attrib_command(
            "attrib +r C:\\Temp\\a.txt"
        ));
    }
}
