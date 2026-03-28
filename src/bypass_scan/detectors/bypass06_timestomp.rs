use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, query_event_records, query_ntfs_volume_metadata,
    query_usn_journal_states, truncate_text,
};

const EXPLICIT_TIMESTOMP_NEEDLES: &[&str] = &[
    "setcreationtime(",
    "setlastwritetime(",
    "setlastaccesstime(",
    "setfiletime",
    "nircmd",
    " timestomp.exe",
    "\\timestomp ",
    "/timestomp",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        6,
        "bypass06_timestomp",
        "Timestamp tampering (LastWriteTime)",
        "No high-confidence timestomp command traces found in available telemetry.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 360);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 260);
    let sysmon_time_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[2], 160);

    let command_hits = collect_timestomp_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);
    let sysmon_hits = collect_sysmon_event2_hits(&sysmon_time_events);

    let usn_states = query_usn_journal_states();
    let ntfs_meta = query_ntfs_volume_metadata();

    if !command_hits.is_empty() && !sysmon_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Timestomp command traces correlate with Sysmon file creation-time change events."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary = "Found timestamp-changing command(s), but no matching Sysmon EventID 2 in the current retention window.".to_string();
    } else if !sysmon_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Sysmon EventID 2 shows file creation-time changes; originating command should be validated."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} timestomp command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !sysmon_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 2".to_string(),
            summary: format!("{} file creation-time change event(s)", sysmon_hits.len()),
            details: sysmon_hits.join("; "),
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
            "Correlate with MFT/USN/LNK timelines for the same file paths before final attribution."
                .to_string(),
        );
        result.recommendations.push(
            "Preserve raw event logs and Sysmon data quickly to avoid rollover of high-value timeline evidence."
                .to_string(),
        );
    }

    logger.log(
        "bypass06_timestomp",
        "info",
        "timestomp checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "sysmon_event2_hits": sysmon_hits.len(),
            "usn_volumes": usn_states.len(),
            "ntfs_volumes": ntfs_meta.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_timestomp_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_timestomp_command(&normalized) {
                continue;
            }

            let image = extract_event_data_value(&event.raw_xml, "Image")
                .or_else(|| extract_event_data_value(&event.raw_xml, "NewProcessName"))
                .or_else(|| extract_event_data_value(&event.raw_xml, "ProcessName"))
                .unwrap_or_else(|| "unknown_process".to_string());
            let cmd = extract_event_data_value(&event.raw_xml, "CommandLine")
                .or_else(|| extract_event_data_value(&event.raw_xml, "ScriptBlockText"))
                .or_else(|| extract_event_data_value(&event.raw_xml, "Payload"))
                .unwrap_or_else(|| event.message.clone());

            hits.push(format!(
                "{} | {} Event {} | process={} | cmd={}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&image, 90),
                truncate_text(&cmd.replace('\n', " "), 180),
            ));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn collect_sysmon_event2_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();
    for event in events {
        let target = extract_event_data_value(&event.raw_xml, "TargetFilename")
            .or_else(|| extract_event_data_value(&event.raw_xml, "TargetFileName"))
            .unwrap_or_default();
        let image = extract_event_data_value(&event.raw_xml, "Image").unwrap_or_default();
        out.push(format!(
            "{} | target={} process={}",
            event.time_created,
            truncate_text(&target, 120),
            truncate_text(&image, 80),
        ));
    }
    out
}

fn looks_like_timestomp_command(text: &str) -> bool {
    let normalized = text.to_lowercase();

    let explicit_match = EXPLICIT_TIMESTOMP_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle));
    if explicit_match {
        return true;
    }

    let set_item_property_timestomp = normalized.contains("set-itemproperty")
        && (normalized.contains("lastwritetime")
            || normalized.contains("creationtime")
            || normalized.contains("lastaccesstime")
            || normalized.contains("-name lastwrite")
            || normalized.contains("-name creation")
            || normalized.contains("-name lastaccess"));
    if set_item_property_timestomp {
        return true;
    }

    let direct_property_assignment = normalized.contains("lastwritetime=")
        || normalized.contains("lastwritetime =")
        || normalized.contains("creationtime=")
        || normalized.contains("creationtime =")
        || normalized.contains("lastaccesstime=")
        || normalized.contains("lastaccesstime =");
    if direct_property_assignment {
        return true;
    }

    let setter_value_shape = (normalized.contains("-name lastwritetime")
        || normalized.contains("-name creationtime")
        || normalized.contains("-name lastaccesstime"))
        && normalized.contains("-value");
    if setter_value_shape {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::looks_like_timestomp_command;

    #[test]
    fn timestomp_matcher_detects_setfiletime_variants() {
        assert!(looks_like_timestomp_command(
            "$f.LastWriteTime = Get-Date '2001-01-01'"
        ));
        assert!(looks_like_timestomp_command(
            "[System.IO.File]::SetCreationTime('a.txt',(Get-Date))"
        ));
        assert!(looks_like_timestomp_command(
            "Set-ItemProperty -Path C:\\temp\\a.txt -Name LastWriteTime -Value (Get-Date)"
        ));
        assert!(!looks_like_timestomp_command(
            "Set-ItemProperty HKCU:\\Software\\Foo -Name Bar -Value Baz"
        ));
        assert!(!looks_like_timestomp_command(
            "git hash-object -- src/bypass_scan/detectors/bypass06_timestomp.rs"
        ));
        assert!(!looks_like_timestomp_command(
            "$recent = Get-ChildItem $env:APPDATA\\Microsoft\\Windows\\Recent | Sort-Object LastWriteTime"
        ));
        assert!(!looks_like_timestomp_command("Get-ChildItem C:\\"));
    }
}
