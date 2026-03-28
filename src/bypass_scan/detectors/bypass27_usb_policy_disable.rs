use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const USBSTOR_SERVICE: &str = r"SYSTEM\CurrentControlSet\Services\USBSTOR";
const REMOVABLE_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        27,
        "bypass27_usb_policy_disable",
        "USB storage policy tampering",
        "No high-confidence USB policy tampering evidence found.",
    );

    let usbstor_start = read_dword(USBSTOR_SERVICE, "Start");
    let deny_all = read_dword(REMOVABLE_POLICY, "Deny_All");
    let deny_read = read_dword(REMOVABLE_POLICY, "Deny_Read");
    let deny_write = read_dword(REMOVABLE_POLICY, "Deny_Write");

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 220);
    reg_events.extend(query_event_records("Security", &[4657], 220));
    let registry_hits = collect_usb_registry_event_hits(&reg_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        240,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let command_hits = collect_usb_disable_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let blocked_state = usbstor_start == Some(4)
        || deny_all == Some(1)
        || deny_read == Some(1)
        || deny_write == Some(1);

    if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected explicit USB-disable policy commands.".to_string();
    } else if !registry_hits.is_empty() && blocked_state {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "USB-related registry modifications detected with currently blocked USB policy state."
                .to_string();
    } else if !registry_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "USB policy/registry modifications observed, but disable intent is not conclusive."
                .to_string();
    } else if blocked_state {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "USB storage appears blocked by current configuration without tamper telemetry."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} USB disable command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry tamper telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} relevant registry event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Registry current state".to_string(),
        summary: format!(
            "USBSTOR Start={} Deny_All={} Deny_Read={} Deny_Write={}",
            opt_u32(usbstor_start),
            opt_u32(deny_all),
            opt_u32(deny_read),
            opt_u32(deny_write)
        ),
        details:
            "State alone may be legitimate hardening; command/event correlation is required for high confidence."
                .to_string(),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate USB policy changes with user/session/process context and SetupAPI/USB timeline artifacts."
                .to_string(),
        );
    }

    logger.log(
        "bypass27_usb_policy_disable",
        "info",
        "usb policy checks complete",
        serde_json::json!({
            "registry_hits": registry_hits.len(),
            "command_hits": command_hits.len(),
            "usbstor_start": usbstor_start,
            "deny_all": deny_all,
            "deny_read": deny_read,
            "deny_write": deny_write,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn read_dword(path: &str, name: &str) -> Option<u32> {
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hk.open_subkey_with_flags(path, KEY_READ).ok()?;
    key.get_value::<u32, _>(name).ok()
}

fn collect_usb_registry_event_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains("usbstor")
            || normalized.contains("removablestoragedevices")
            || normalized.contains("deny_all")
            || normalized.contains("deny_read")
            || normalized.contains("deny_write")
        {
            hits.push(format!(
                "{} | Event {} | {}",
                event.time_created,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }
    hits
}

fn collect_usb_disable_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_usb_disable_command(&normalized) {
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

fn looks_like_usb_disable_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let usbstor_disable = normalized.contains("usbstor")
        && normalized.contains("start")
        && (normalized.contains(" 4")
            || normalized.contains("0x4")
            || normalized.contains("-value 4")
            || normalized.contains("/d 4"));

    let removable_policy_disable = normalized.contains("removablestoragedevices")
        && ((normalized.contains("deny_all")
            || normalized.contains("deny_read")
            || normalized.contains("deny_write"))
            && (normalized.contains(" 1")
                || normalized.contains("0x1")
                || normalized.contains("-value 1")
                || normalized.contains("/d 1")));

    usbstor_disable || removable_policy_disable
}

fn opt_u32(value: Option<u32>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::looks_like_usb_disable_command;

    #[test]
    fn usb_disable_command_matcher_detects_disable_values() {
        assert!(looks_like_usb_disable_command(
            "reg add HKLM\\...\\USBSTOR /v Start /t REG_DWORD /d 4 /f"
        ));
        assert!(looks_like_usb_disable_command(
            "Set-ItemProperty HKLM:\\...\\RemovableStorageDevices -Name Deny_All -Value 1"
        ));
        assert!(!looks_like_usb_disable_command(
            "reg add HKLM\\...\\USBSTOR /v Start /t REG_DWORD /d 3 /f"
        ));
    }
}
