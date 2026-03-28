use std::fs;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        17,
        "bypass17_registry_usb_deletion",
        "USBSTOR registry tampering",
        "No high-confidence USBSTOR deletion events found.",
    );

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 260);
    reg_events.extend(query_event_records("Security", &[4657], 260));
    let registry_hits = collect_usbstor_registry_hits(&reg_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_usbstor_delete_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let setupapi_refs = count_setupapi_usbstor_refs();
    let usbstor_branch_present = usbstor_branch_present();

    if !registry_hits.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "USBSTOR registry delete commands correlate with direct registry tamper events."
                .to_string();
    } else if !command_hits.is_empty() || !registry_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary = "USBSTOR registry tamper telemetry detected.".to_string();
    } else if setupapi_refs > 0 && !usbstor_branch_present {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "USBSTOR branch is missing despite SetupAPI USB history (possible prior cleanup)."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} USBSTOR delete command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} USBSTOR tamper event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "USB artifact state".to_string(),
        summary: format!(
            "setupapi_usbstor_refs={} usbstor_branch_present={}",
            setupapi_refs, usbstor_branch_present
        ),
        details: String::new(),
    });

    logger.log(
        "bypass17_registry_usb_deletion",
        "info",
        "usb registry tamper check complete",
        serde_json::json!({
            "registry_hits": registry_hits.len(),
            "command_hits": command_hits.len(),
            "setupapi_usbstor_refs": setupapi_refs,
            "usbstor_branch_present": usbstor_branch_present,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_usbstor_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();

    for event in events {
        let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if (text.contains("usbstor") || text.contains("\\enum\\usb"))
            && (text.contains("delete")
                || text.contains("removed")
                || event.event_id == 12
                || event.event_id == 4657)
        {
            hits.push(format!(
                "{} | Event {} | {}",
                event.time_created,
                event.event_id,
                truncate_text(&event.message, 220)
            ));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn collect_usbstor_delete_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_usbstor_delete_command(&text) {
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

fn looks_like_usbstor_delete_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target = normalized.contains("usbstor") || normalized.contains("\\enum\\usb");
    let delete = normalized.contains("reg delete")
        || normalized.contains("remove-item")
        || normalized.contains("remove-itemproperty")
        || normalized.contains("deletekey");
    target && delete
}

fn count_setupapi_usbstor_refs() -> usize {
    let log_path = r"C:\Windows\INF\setupapi.dev.log";
    let Ok(bytes) = fs::read(log_path) else {
        return 0;
    };
    let text = String::from_utf8_lossy(&bytes).to_lowercase();
    text.matches("usbstor\\").count()
}

fn usbstor_branch_present() -> bool {
    let path = r"HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR";
    crate::bypass_scan::utils::run_powershell(&format!("Test-Path '{path}'"))
        .map(|v| v.to_lowercase().contains("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::looks_like_usbstor_delete_command;

    #[test]
    fn usbstor_delete_command_matcher_detects_registry_delete_shape() {
        assert!(looks_like_usbstor_delete_command(
            "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f"
        ));
        assert!(looks_like_usbstor_delete_command(
            "Remove-Item HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB -Recurse -Force"
        ));
        assert!(!looks_like_usbstor_delete_command(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
        ));
    }
}
