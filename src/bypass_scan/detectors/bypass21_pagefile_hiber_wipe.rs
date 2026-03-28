use std::fs;
use std::path::Path;

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const MEM_MGMT: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const COMMAND_MARKERS: &[&str] = &[
    "powercfg",
    "/h",
    "off",
    "clearpagefileatshutdown",
    "set-itemproperty",
    "reg add",
    "pagingfiles",
    "wmic pagefileset",
    "remove-itemproperty",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        21,
        "bypass21_pagefile_hiber_wipe",
        "Pagefile/hibernation anti-forensic changes",
        "No direct anti-forensic pagefile/hibernation command traces found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let command_hits = collect_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let reg_state = read_memory_management_state();
    let pagefile_state = read_file_state(r"C:\pagefile.sys");
    let hiberfile_state = read_file_state(r"C:\hiberfil.sys");

    if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected command traces that can disable hibernation or wipe pagefile residue."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} pagefile/hiber command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if reg_state.clear_pagefile_at_shutdown == Some(1)
        && !hiberfile_state.exists
        && pagefile_state.exists
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Memory residue hardening settings are active; validate whether this is policy-driven."
                .to_string();
    } else if reg_state.clear_pagefile_at_shutdown == Some(1) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Potential pagefile/hibernation anti-forensic posture detected without direct command traces."
                .to_string();
    }

    result.evidence.push(EvidenceItem {
        source: format!("HKLM\\{}", MEM_MGMT),
        summary: format!(
            "ClearPageFileAtShutdown={} PagingFiles={}",
            reg_state
                .clear_pagefile_at_shutdown
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            if reg_state.paging_files.is_empty() {
                "[]".to_string()
            } else {
                reg_state.paging_files.join(", ")
            }
        ),
        details: format!(
            "LargeSystemCache={} ExistingPageFiles={}",
            reg_state
                .large_system_cache
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            if reg_state.existing_page_files.is_empty() {
                "[]".to_string()
            } else {
                reg_state.existing_page_files.join(", ")
            }
        ),
    });

    result.evidence.push(EvidenceItem {
        source: r"C:\pagefile.sys".to_string(),
        summary: format!(
            "exists={} size={}",
            pagefile_state.exists,
            pagefile_state
                .size
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: pagefile_state
            .modified_utc
            .unwrap_or_else(|| "unknown_modified_time".to_string()),
    });

    result.evidence.push(EvidenceItem {
        source: r"C:\hiberfil.sys".to_string(),
        summary: format!(
            "exists={} size={}",
            hiberfile_state.exists,
            hiberfile_state
                .size
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: hiberfile_state
            .modified_utc
            .unwrap_or_else(|| "unknown_modified_time".to_string()),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate with VSS/EventLog cleanup and process lineage to separate policy hardening from anti-forensic intent."
                .to_string(),
        );
        result.recommendations.push(
            "If command-line auditing is limited, enable centralized logging for PowerShell and process creation."
                .to_string(),
        );
    }

    logger.log(
        "bypass21_pagefile_hiber_wipe",
        "info",
        "pagefile/hiber checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "clear_pagefile": reg_state.clear_pagefile_at_shutdown,
            "paging_files_count": reg_state.paging_files.len(),
            "pagefile_exists": pagefile_state.exists,
            "hiberfile_exists": hiberfile_state.exists,
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone)]
struct MemoryManagementState {
    clear_pagefile_at_shutdown: Option<u32>,
    large_system_cache: Option<u32>,
    paging_files: Vec<String>,
    existing_page_files: Vec<String>,
}

#[derive(Debug, Clone)]
struct ArtifactFileState {
    exists: bool,
    size: Option<u64>,
    modified_utc: Option<String>,
}

fn read_memory_management_state() -> MemoryManagementState {
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hk.open_subkey_with_flags(MEM_MGMT, KEY_READ).ok();

    let clear_pagefile_at_shutdown = key
        .as_ref()
        .and_then(|k| k.get_value::<u32, _>("ClearPageFileAtShutdown").ok());
    let large_system_cache = key
        .as_ref()
        .and_then(|k| k.get_value::<u32, _>("LargeSystemCache").ok());
    let paging_files = key
        .as_ref()
        .and_then(|k| k.get_value::<Vec<String>, _>("PagingFiles").ok())
        .unwrap_or_default();
    let existing_page_files = key
        .as_ref()
        .and_then(|k| k.get_value::<Vec<String>, _>("ExistingPageFiles").ok())
        .unwrap_or_default();

    MemoryManagementState {
        clear_pagefile_at_shutdown,
        large_system_cache,
        paging_files,
        existing_page_files,
    }
}

fn read_file_state(path: &str) -> ArtifactFileState {
    let p = Path::new(path);
    let metadata = fs::metadata(p).ok();

    ArtifactFileState {
        exists: metadata.is_some(),
        size: metadata.as_ref().map(|m| m.len()),
        modified_utc: metadata
            .and_then(|m| m.modified().ok())
            .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
    }
}

fn collect_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_pagefile_hiber_command(&normalized) {
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

fn looks_like_pagefile_hiber_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let has_marker = COMMAND_MARKERS
        .iter()
        .any(|needle| normalized.contains(needle));
    if !has_marker {
        return false;
    }

    (normalized.contains("powercfg") && normalized.contains("off") && normalized.contains("/h"))
        || (normalized.contains("clearpagefileatshutdown") && normalized.contains("1"))
        || (normalized.contains("pagingfiles")
            && (normalized.contains("reg add")
                || normalized.contains("set-itemproperty")
                || normalized.contains("remove-itemproperty")))
        || (normalized.contains("wmic pagefileset")
            && (normalized.contains("delete")
                || normalized.contains("set")
                || normalized.contains("automaticmanagedpagefile")))
}

#[cfg(test)]
mod tests {
    use super::looks_like_pagefile_hiber_command;

    #[test]
    fn command_matcher_detects_hiber_and_pagefile_changes() {
        assert!(looks_like_pagefile_hiber_command("powercfg /h off"));
        assert!(looks_like_pagefile_hiber_command(
            "reg add HKLM\\...\\Memory Management /v ClearPageFileAtShutdown /t REG_DWORD /d 1"
        ));
        assert!(!looks_like_pagefile_hiber_command("powercfg /l"));
    }
}
