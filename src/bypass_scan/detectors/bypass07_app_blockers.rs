use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::keywords::contains_tool_keyword;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const IFEO_PATHS: &[&str] = &[
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        7,
        "bypass07_app_blockers",
        "Application launch blockers",
        "No targeted launch-blocking configuration found.",
    );

    let ifeo_entries = collect_ifeo_debuggers();
    let targeted_ifeo = ifeo_entries
        .iter()
        .filter(|e| contains_tool_keyword(e))
        .cloned()
        .collect::<Vec<_>>();

    let mut targeted_events = Vec::new();
    let mut generic_events = Vec::new();

    for channel in [
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-AppLocker/MSI and Script",
    ] {
        for event in query_event_records(channel, &[8004], 120) {
            let line = format!(
                "{} | Event {} | {}",
                channel,
                event.event_id,
                truncate_text(&event.message, 200)
            );
            if contains_tool_keyword(&event.message) {
                targeted_events.push(line);
            } else {
                generic_events.push(line);
            }
        }
    }

    for event in query_event_records("Application", &[865, 866, 867, 868], 180) {
        let line = format!(
            "Application | Event {} | {}",
            event.event_id,
            truncate_text(&event.message, 200)
        );
        if contains_tool_keyword(&event.message) {
            targeted_events.push(line);
        } else {
            generic_events.push(line);
        }
    }

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_blocker_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 260);
    reg_events.extend(query_event_records("Security", &[4657], 260));
    let ifeo_registry_hits = collect_ifeo_registry_hits(&reg_events);

    if !targeted_ifeo.is_empty() || !targeted_events.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected targeted application-blocking artifacts for scanner/forensic tools."
                .to_string();
    } else if !ifeo_entries.is_empty()
        && (!command_hits.is_empty()
            || !ifeo_registry_hits.is_empty()
            || !generic_events.is_empty())
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Application-blocking controls found with modification or block-event telemetry."
                .to_string();
    } else if !ifeo_entries.is_empty() || !command_hits.is_empty() || !ifeo_registry_hits.is_empty()
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Single application-blocker indicator detected (IFEO/config/telemetry).".to_string();
    }

    if !targeted_ifeo.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "IFEO Debugger".to_string(),
            summary: format!("{} targeted IFEO debugger entries", targeted_ifeo.len()),
            details: targeted_ifeo.join("; "),
        });
    }

    if !ifeo_entries.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "IFEO Debugger".to_string(),
            summary: format!("{} IFEO debugger entries", ifeo_entries.len()),
            details: ifeo_entries
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !targeted_events.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "AppLocker/SRP events".to_string(),
            summary: format!("{} targeted block events", targeted_events.len()),
            details: targeted_events.join("; "),
        });
    } else if !generic_events.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "AppLocker/SRP events".to_string(),
            summary: format!("{} generic block events", generic_events.len()),
            details: generic_events
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} IFEO/AppLocker command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !ifeo_registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry tamper telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} IFEO registry event(s)", ifeo_registry_hits.len()),
            details: ifeo_registry_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Remove unauthorized IFEO/AppLocker/SRP rules and export policy for audit.".to_string(),
        );
    }

    logger.log(
        "bypass07_app_blockers",
        "info",
        "app blocker analysis complete",
        serde_json::json!({
            "ifeo_entries": ifeo_entries.len(),
            "targeted_ifeo": targeted_ifeo.len(),
            "targeted_events": targeted_events.len(),
            "generic_events": generic_events.len(),
            "command_hits": command_hits.len(),
            "ifeo_registry_hits": ifeo_registry_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_ifeo_debuggers() -> Vec<String> {
    let mut out = Vec::new();
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);

    for path in IFEO_PATHS {
        let Ok(base) = hk.open_subkey_with_flags(path, KEY_READ) else {
            continue;
        };

        for sub in base.enum_keys().flatten() {
            let Ok(app_key) = base.open_subkey_with_flags(&sub, KEY_READ) else {
                continue;
            };
            if let Ok(debugger) = app_key.get_value::<String, _>("Debugger") {
                out.push(format!("{}\\{} -> {}", path, sub, debugger));
            }
        }
    }

    out
}

fn collect_blocker_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_blocker_command(&normalized) {
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

fn looks_like_blocker_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let ifeo_mutation = normalized.contains("image file execution options")
        && normalized.contains("debugger")
        && (normalized.contains("reg add")
            || normalized.contains("set-itemproperty")
            || normalized.contains("new-itemproperty"));
    let applocker_mutation = normalized.contains("applocker")
        && (normalized.contains("set-applockerpolicy")
            || normalized.contains("new-applockerpolicy")
            || normalized.contains("merge-applockerpolicy"));
    ifeo_mutation || applocker_mutation
}

fn collect_ifeo_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains("image file execution options") || normalized.contains("\\ifeo\\") {
            out.push(format!(
                "{} | Event {} | {}",
                event.time_created,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::looks_like_blocker_command;

    #[test]
    fn blocker_command_matcher_detects_ifeo_and_applocker_mutation() {
        assert!(looks_like_blocker_command(
            "reg add HKLM\\...\\Image File Execution Options\\procmon.exe /v Debugger /d cmd.exe /f",
        ));
        assert!(looks_like_blocker_command(
            "Set-AppLockerPolicy -XMLPolicy policy.xml -Merge",
        ));
        assert!(!looks_like_blocker_command(
            "Get-AppLockerPolicy -Effective"
        ));
    }
}
