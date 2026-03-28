use std::fs;

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        37,
        "bypass37_fake_usb_artifacts",
        "Fake USB artifacts / USBSTOR inconsistency",
        "No strong SetupAPI/registry/device inconsistency found.",
    );

    let setupapi_usbstor_refs = count_setupapi_usbstor_refs();
    let reg_usbstor_keys = count_registry_subkeys(r"SYSTEM\CurrentControlSet\Enum\USBSTOR");
    let reg_usb_keys = count_registry_subkeys(r"SYSTEM\CurrentControlSet\Enum\USB");
    let mounted_usb_values = count_mounteddevices_usb_values();
    let sec_device_events = query_event_records("Security", &[6416], 260);
    let sec_device_usb_count = sec_device_events
        .iter()
        .filter(|ev| {
            let text = format!("{} {}", ev.message, ev.raw_xml).to_lowercase();
            text.contains("usb") || text.contains("usbstor") || text.contains("hid")
        })
        .count();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_proc_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let delete_command_hits = collect_usb_artifact_delete_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_proc_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 260);
    reg_events.extend(query_event_records("Security", &[4657], 260));
    let reg_tamper_hits = collect_usb_registry_tamper_hits(&reg_events);

    let hard_inconsistency = setupapi_usbstor_refs > 0
        && reg_usbstor_keys == 0
        && (reg_usb_keys > 0 || mounted_usb_values > 0 || sec_device_usb_count > 0);
    let soft_inconsistency = setupapi_usbstor_refs > 0
        && reg_usbstor_keys == 0
        && (reg_usb_keys > 0 || sec_device_usb_count > 0);

    if hard_inconsistency && (!delete_command_hits.is_empty() || !reg_tamper_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Strong USB artifact inconsistency with explicit USB registry deletion/tamper traces."
                .to_string();
    } else if hard_inconsistency {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Strong USB artifact inconsistency: SetupAPI/device evidence exists while USBSTOR registry is empty."
                .to_string();
    } else if soft_inconsistency {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Potential USB artifact inconsistency detected; missing USBSTOR branch requires manual timeline validation."
                .to_string();
    } else if !delete_command_hits.is_empty() || !reg_tamper_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "USB artifact deletion/tamper commands found without full cross-source inconsistency."
                .to_string();
    }

    if !delete_command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!(
                "{} USB artifact delete command hit(s)",
                delete_command_hits.len()
            ),
            details: delete_command_hits.join("; "),
        });
    }

    if !reg_tamper_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry tamper telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} USB registry tamper event(s)", reg_tamper_hits.len()),
            details: reg_tamper_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "USB artifact source consistency".to_string(),
        summary: format!(
            "setupapi_usbstor_refs={} reg_usbstor_keys={} reg_usb_keys={} mounted_usb_values={} security6416_usb_events={}",
            setupapi_usbstor_refs,
            reg_usbstor_keys,
            reg_usb_keys,
            mounted_usb_values,
            sec_device_usb_count
        ),
        details: "Cross-source mismatch indicates possible fake artifact planting or selective registry cleanup."
            .to_string(),
    });

    logger.log(
        "bypass37_fake_usb_artifacts",
        "info",
        "fake usb artifact checks complete",
        serde_json::json!({
            "setupapi_usbstor_refs": setupapi_usbstor_refs,
            "reg_usbstor_keys": reg_usbstor_keys,
            "reg_usb_keys": reg_usb_keys,
            "mounted_usb_values": mounted_usb_values,
            "security6416_usb_events": sec_device_usb_count,
            "delete_command_hits": delete_command_hits.len(),
            "reg_tamper_hits": reg_tamper_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn count_setupapi_usbstor_refs() -> usize {
    let log_path = r"C:\Windows\INF\setupapi.dev.log";
    let Ok(bytes) = fs::read(log_path) else {
        return 0;
    };
    let text = String::from_utf8_lossy(&bytes).to_lowercase();
    text.matches("usbstor\\").count()
}

fn count_registry_subkeys(path: &str) -> usize {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(path, KEY_READ) else {
        return 0;
    };

    key.enum_keys().flatten().count()
}

fn count_mounteddevices_usb_values() -> usize {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(r"SYSTEM\MountedDevices", KEY_READ) else {
        return 0;
    };

    key.enum_values()
        .flatten()
        .filter(|(name, _)| name.to_lowercase().contains("usb"))
        .count()
}

fn collect_usb_artifact_delete_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_usb_artifact_delete_command(&text) {
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

fn looks_like_usb_artifact_delete_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let targets_usb = normalized.contains("usbstor")
        || normalized.contains("\\enum\\usb")
        || normalized.contains("mounteddevices");
    let delete_shape = normalized.contains("reg delete")
        || normalized.contains("remove-item")
        || normalized.contains("remove-itemproperty")
        || normalized.contains("deletekey")
        || normalized.contains("clear-itemproperty");
    targets_usb && delete_shape
}

fn collect_usb_registry_tamper_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains("usbstor")
            || normalized.contains("\\enum\\usb")
            || normalized.contains("mounteddevices")
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

#[cfg(test)]
mod tests {
    use super::looks_like_usb_artifact_delete_command;

    #[test]
    fn usb_delete_command_matcher_requires_target_and_delete_shape() {
        assert!(looks_like_usb_artifact_delete_command(
            "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f"
        ));
        assert!(looks_like_usb_artifact_delete_command(
            "Remove-Item HKLM:\\SYSTEM\\MountedDevices -Force"
        ));
        assert!(!looks_like_usb_artifact_delete_command(
            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
        ));
    }
}
