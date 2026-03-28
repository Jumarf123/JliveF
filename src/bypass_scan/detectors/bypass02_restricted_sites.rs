use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD};

use crate::bypass_scan::keywords::contains_domain_keyword;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const ZONEMAP_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains",
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains",
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Ranges",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        2,
        "bypass02_restricted_sites",
        "Restricted Sites policy abuse",
        "No suspicious restricted-site mappings detected.",
    );

    let mut all_entries = Vec::new();

    for path in ZONEMAP_PATHS {
        all_entries.extend(collect_zone_entries(HKEY_CURRENT_USER, path, "HKCU"));
        all_entries.extend(collect_zone_entries(HKEY_LOCAL_MACHINE, path, "HKLM"));
    }

    let targeted = all_entries
        .iter()
        .filter(|entry| contains_domain_keyword(entry))
        .cloned()
        .collect::<Vec<_>>();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_restricted_sites_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 260);
    reg_events.extend(query_event_records("Security", &[4657], 260));
    let registry_hits = collect_zonemap_registry_hits(&reg_events);

    if !targeted.is_empty() && (!command_hits.is_empty() || !registry_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Restricted Sites includes targeted domains with direct registry/command tamper telemetry."
                .to_string();
    } else if !targeted.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Restricted Sites contains entries targeting scanner/forensic-related domains."
                .to_string();
    } else if !all_entries.is_empty() && (!command_hits.is_empty() || !registry_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Restricted Sites entries detected with command/registry modification traces."
                .to_string();
    } else if !all_entries.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Restricted Sites list is not empty (single-indicator bypass policy).".to_string();
    }

    if !all_entries.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry ZoneMap".to_string(),
            summary: format!("{} zone=4 entry(s)", all_entries.len()),
            details: all_entries
                .iter()
                .take(60)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !targeted.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry ZoneMap".to_string(),
            summary: format!("{} targeted entry(s)", targeted.len()),
            details: targeted.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} ZoneMap command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry tamper telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} ZoneMap registry event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Validate ZoneMap entries against approved GPO baseline and remove unauthorized restricted mappings."
                .to_string(),
        );
    }

    logger.log(
        "bypass02_restricted_sites",
        "info",
        "zonemap analyzed",
        serde_json::json!({
            "entries": all_entries.len(),
            "targeted": targeted.len(),
            "command_hits": command_hits.len(),
            "registry_hits": registry_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_zone_entries(root: HKEY, path: &str, root_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let hive = RegKey::predef(root);
    let Ok(key) = hive.open_subkey_with_flags(path, KEY_READ) else {
        return out;
    };
    walk_zone_key(&key, root_name, path, &mut out, 0);
    out
}

fn walk_zone_key(key: &RegKey, root_name: &str, path: &str, out: &mut Vec<String>, depth: usize) {
    if depth > 8 {
        return;
    }

    for value in key.enum_values().flatten() {
        let name = value.0;
        let reg = value.1;
        if reg.vtype != REG_DWORD || reg.bytes.len() < 4 {
            continue;
        }

        let zone = u32::from_le_bytes([reg.bytes[0], reg.bytes[1], reg.bytes[2], reg.bytes[3]]);
        if zone == 4 {
            out.push(format!("{}\\{} [{}]=4", root_name, path, name));
        }
    }

    for sub in key.enum_keys().flatten() {
        if let Ok(subkey) = key.open_subkey_with_flags(&sub, KEY_READ) {
            let next = format!("{}\\{}", path, sub);
            walk_zone_key(&subkey, root_name, &next, out, depth + 1);
        }
    }
}

fn collect_restricted_sites_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_restricted_sites_command(&text) {
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

fn looks_like_restricted_sites_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let targets_zonemap = normalized.contains("zonemap")
        && (normalized.contains("domains")
            || normalized.contains("escdomains")
            || normalized.contains("ranges"));

    let sets_zone4 = normalized.contains(" /d 4")
        || normalized.contains("-value 4")
        || normalized.contains("=4")
        || normalized.contains("zone=4");

    let mutator = normalized.contains("reg add")
        || normalized.contains("set-itemproperty")
        || normalized.contains("new-itemproperty");

    targets_zonemap && mutator && sets_zone4
}

fn collect_zonemap_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();

    for event in events {
        let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if text.contains("zonemap")
            && (text.contains("domains") || text.contains("escdomains") || text.contains("ranges"))
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
    use super::looks_like_restricted_sites_command;

    #[test]
    fn restricted_sites_command_matcher_requires_zonemap_mutation_to_zone4() {
        assert!(looks_like_restricted_sites_command(
            "reg add HKCU\\...\\ZoneMap\\Domains\\example.com /v http /t REG_DWORD /d 4 /f",
        ));
        assert!(looks_like_restricted_sites_command(
            "Set-ItemProperty HKCU:\\...\\ZoneMap\\Domains\\example.com -Name http -Value 4",
        ));
        assert!(!looks_like_restricted_sites_command(
            "reg query HKCU\\...\\ZoneMap\\Domains",
        ));
    }
}
