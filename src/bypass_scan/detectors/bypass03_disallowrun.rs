use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::keywords::contains_tool_keyword;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const EXPLORER_POLICY: &str = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        3,
        "bypass03_disallowrun",
        "DisallowRun/RestrictRun policy abuse",
        "No suspicious application blocking policy detected.",
    );

    let mut entries = Vec::new();
    entries.extend(read_policy_entries(HKEY_CURRENT_USER, "HKCU"));
    entries.extend(read_policy_entries(HKEY_LOCAL_MACHINE, "HKLM"));

    let targeted = entries
        .iter()
        .filter(|entry| contains_tool_keyword(entry))
        .cloned()
        .collect::<Vec<_>>();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_disallowrun_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 260);
    reg_events.extend(query_event_records("Security", &[4657], 260));
    let registry_hits = collect_disallowrun_registry_hits(&reg_events);

    if !targeted.is_empty() && (!command_hits.is_empty() || !registry_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Policy blocks forensic/scanner tools with direct command/registry tamper traces."
                .to_string();
    } else if !targeted.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Policy explicitly blocks forensic/scanner tools.".to_string();
    } else if !entries.is_empty() && (!command_hits.is_empty() || !registry_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "DisallowRun/RestrictRun policy exists with command/registry modification telemetry."
                .to_string();
    } else if !entries.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "DisallowRun/RestrictRun policy exists (single-indicator bypass policy).".to_string();
    }

    if !entries.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Explorer Policies".to_string(),
            summary: format!("{} blocked app entry(s)", entries.len()),
            details: entries
                .iter()
                .take(60)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !targeted.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Explorer Policies".to_string(),
            summary: format!("{} targeted blocked app entry(s)", targeted.len()),
            details: targeted.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} DisallowRun command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry tamper telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} DisallowRun registry event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Remove unauthorized DisallowRun/RestrictRun entries and re-apply approved policy baseline."
                .to_string(),
        );
    }

    logger.log(
        "bypass03_disallowrun",
        "info",
        "policy scanned",
        serde_json::json!({
            "entries": entries.len(),
            "targeted": targeted.len(),
            "command_hits": command_hits.len(),
            "registry_hits": registry_hits.len(),
            "status": result.status.as_label()
        }),
    );

    result
}

fn read_policy_entries(root: HKEY, root_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let hive = RegKey::predef(root);
    let Ok(explorer) = hive.open_subkey_with_flags(EXPLORER_POLICY, KEY_READ) else {
        return out;
    };

    for mode in ["DisallowRun", "RestrictRun"] {
        let enabled = explorer.get_value::<u32, _>(mode).unwrap_or(0);
        let Ok(list_key) = explorer.open_subkey_with_flags(mode, KEY_READ) else {
            continue;
        };

        for value in list_key.enum_values().flatten() {
            if let Ok(name) = list_key.get_value::<String, _>(value.0.clone()) {
                out.push(format!(
                    "{}\\{}\\{} = {} (enabled={})",
                    root_name, EXPLORER_POLICY, mode, name, enabled
                ));
            }
        }
    }

    out
}

fn collect_disallowrun_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_disallowrun_command(&text) {
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

fn looks_like_disallowrun_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target = normalized.contains("policies\\explorer")
        && (normalized.contains("disallowrun") || normalized.contains("restrictrun"));
    let mutator = normalized.contains("reg add")
        || normalized.contains("set-itemproperty")
        || normalized.contains("new-itemproperty");
    target && mutator
}

fn collect_disallowrun_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();
    for event in events {
        let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if text.contains("policies\\explorer")
            && (text.contains("disallowrun") || text.contains("restrictrun"))
        {
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
    use super::looks_like_disallowrun_command;

    #[test]
    fn disallowrun_command_matcher_requires_policy_target_and_mutation() {
        assert!(looks_like_disallowrun_command(
            "reg add HKCU\\...\\Policies\\Explorer\\DisallowRun /v 1 /d Procmon.exe /f",
        ));
        assert!(looks_like_disallowrun_command(
            "Set-ItemProperty HKCU:\\...\\Policies\\Explorer\\RestrictRun -Name 1 -Value cmd.exe",
        ));
        assert!(!looks_like_disallowrun_command(
            "reg query HKCU\\...\\Policies\\Explorer\\DisallowRun",
        ));
    }
}
