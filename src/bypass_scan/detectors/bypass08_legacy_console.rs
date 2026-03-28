use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, REG_DWORD};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const CONSOLE_KEY: &str = r"Console";

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        8,
        "bypass08_legacy_console",
        "Legacy console mode abuse",
        "Legacy console mode is not enabled in inspected registry keys.",
    );

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(base) = hkcu.open_subkey_with_flags(CONSOLE_KEY, KEY_READ) else {
        result.status = DetectionStatus::Error;
        result.summary = "Failed to open HKCU\\Console".to_string();
        result.error = Some("registry open failed".to_string());
        return result;
    };

    let mut force_v2_disabled = Vec::new();
    let mut shortcuts_disabled = Vec::new();

    walk_console_keys(
        &base,
        CONSOLE_KEY,
        &mut force_v2_disabled,
        &mut shortcuts_disabled,
        0,
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_console_tamper_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    if !force_v2_disabled.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = if !command_hits.is_empty() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        result.summary = "ForceV2=0 detected, indicating legacy console mode usage.".to_string();
    } else if !shortcuts_disabled.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Ctrl shortcuts disabled in console profile with matching command change telemetry."
                .to_string();
    } else if !shortcuts_disabled.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary = "Ctrl key shortcuts are disabled in console profile.".to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Console profile modification commands detected without current registry anomaly."
                .to_string();
    }

    if !force_v2_disabled.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "HKCU\\Console".to_string(),
            summary: format!("{} keys with ForceV2=0", force_v2_disabled.len()),
            details: force_v2_disabled.join("; "),
        });
    }

    if !shortcuts_disabled.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "HKCU\\Console".to_string(),
            summary: format!(
                "{} keys with CtrlKeyShortcutsDisabled=1",
                shortcuts_disabled.len()
            ),
            details: shortcuts_disabled.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} console-profile command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Reset console profile values (ForceV2=1) and verify CMD/PowerShell defaults."
                .to_string(),
        );
    }

    logger.log(
        "bypass08_legacy_console",
        "info",
        "console registry checked",
        serde_json::json!({
            "force_v2_disabled": force_v2_disabled.len(),
            "shortcuts_disabled": shortcuts_disabled.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn walk_console_keys(
    key: &RegKey,
    path: &str,
    force_v2_disabled: &mut Vec<String>,
    shortcuts_disabled: &mut Vec<String>,
    depth: usize,
) {
    if depth > 5 {
        return;
    }

    if let Some(v) = read_dword(key, "ForceV2") {
        if v == 0 {
            force_v2_disabled.push(format!("{path}\\ForceV2=0"));
        }
    }

    if let Some(v) = read_dword(key, "CtrlKeyShortcutsDisabled") {
        if v == 1 {
            shortcuts_disabled.push(format!("{path}\\CtrlKeyShortcutsDisabled=1"));
        }
    }

    for sub in key.enum_keys().flatten() {
        if let Ok(subkey) = key.open_subkey_with_flags(&sub, KEY_READ) {
            let next = format!("{path}\\{sub}");
            walk_console_keys(
                &subkey,
                &next,
                force_v2_disabled,
                shortcuts_disabled,
                depth + 1,
            );
        }
    }
}

fn read_dword(key: &RegKey, name: &str) -> Option<u32> {
    let raw = key.get_raw_value(name).ok()?;
    if raw.vtype != REG_DWORD || raw.bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        raw.bytes[0],
        raw.bytes[1],
        raw.bytes[2],
        raw.bytes[3],
    ]))
}

fn collect_console_tamper_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_console_tamper_command(&normalized) {
                continue;
            }
            out.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_console_tamper_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target = normalized.contains("hkcu\\console")
        || normalized.contains("hkcu:\\console")
        || normalized.contains("forcev2")
        || normalized.contains("ctrlkeyshortcutsdisabled");
    let mutator = normalized.contains("reg add")
        || normalized.contains("set-itemproperty")
        || normalized.contains("new-itemproperty");
    target && mutator
}

#[cfg(test)]
mod tests {
    use super::looks_like_console_tamper_command;

    #[test]
    fn console_command_matcher_requires_console_target_and_mutation() {
        assert!(looks_like_console_tamper_command(
            "reg add HKCU\\Console /v ForceV2 /t REG_DWORD /d 0 /f",
        ));
        assert!(looks_like_console_tamper_command(
            "Set-ItemProperty HKCU:\\Console -Name CtrlKeyShortcutsDisabled -Value 1",
        ));
        assert!(!looks_like_console_tamper_command(
            "reg query HKCU\\Console"
        ));
    }
}
