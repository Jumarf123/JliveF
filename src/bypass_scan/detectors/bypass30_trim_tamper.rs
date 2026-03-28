use regex::Regex;
use serde_json::Value;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, query_event_records, run_command, run_powershell, truncate_text,
};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        30,
        "bypass30_trim_tamper",
        "TRIM/DisableDeleteNotify tamper",
        "No high-confidence TRIM tamper evidence found.",
    );

    let fsutil_out =
        run_command("fsutil", &["behavior", "query", "DisableDeleteNotify"]).unwrap_or_default();
    let fsutil_state = parse_disable_delete_notify(&fsutil_out);
    let has_disabled_state = fsutil_state.iter().any(|(_, value)| *value == 1);
    let storage_media = query_physical_media_types();
    let has_ssd_media = storage_media.iter().any(|m| {
        let lower = m.to_lowercase();
        lower.contains("ssd") || lower.contains("nvme") || lower.contains("scm")
    });

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 300);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_trim_set_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 220);
    reg_events.extend(query_event_records("Security", &[4657], 220));
    let registry_hits = collect_trim_registry_hits(&reg_events);

    if !command_hits.is_empty() && has_disabled_state {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit DisableDeleteNotify=1 command traces and matching current state."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Detected explicit TRIM tamper commands; current state may have been reverted."
                .to_string();
    } else if !registry_hits.is_empty() && has_disabled_state {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "TRIM-related registry/service telemetry correlates with DisableDeleteNotify=1 state."
                .to_string();
    } else if has_disabled_state && has_ssd_media {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "DisableDeleteNotify=1 detected on host with SSD/NVMe media; verify if this was intentional."
                .to_string();
    } else if has_disabled_state {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "DisableDeleteNotify=1 detected. On HDD-only systems this may be benign, but still weak tamper signal."
                .to_string();
    } else if !registry_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "TRIM/defrag-related registry telemetry found without current DisableDeleteNotify=1 state."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!(
                "{} DisableDeleteNotify set command hit(s)",
                command_hits.len()
            ),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} TRIM-related registry event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "fsutil behavior query DisableDeleteNotify".to_string(),
        summary: if fsutil_state.is_empty() {
            "Unable to parse DisableDeleteNotify state".to_string()
        } else {
            fsutil_state
                .iter()
                .map(|(kind, val)| format!("{kind}={val}"))
                .collect::<Vec<_>>()
                .join(" ")
        },
        details: truncate_text(&fsutil_out.replace('\n', " | "), 400),
    });

    if !storage_media.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Get-PhysicalDisk media types".to_string(),
            summary: format!("{} media entries", storage_media.len()),
            details: storage_media.join("; "),
        });
    }

    logger.log(
        "bypass30_trim_tamper",
        "info",
        "trim checks complete",
        serde_json::json!({
            "disable_state": fsutil_state,
            "has_disabled_state": has_disabled_state,
            "has_ssd_media": has_ssd_media,
            "command_hits": command_hits.len(),
            "registry_hits": registry_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn parse_disable_delete_notify(text: &str) -> Vec<(String, u32)> {
    let re = Regex::new(r"(?i)\b([A-Za-z]+)\s+DisableDeleteNotify\s*=\s*([01])").unwrap();
    let mut out = Vec::new();

    for cap in re.captures_iter(text) {
        let kind = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let value = cap
            .get(2)
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(0);
        out.push((kind, value));
    }

    // Legacy output may not include filesystem prefix.
    if out.is_empty() {
        let fallback = Regex::new(r"(?i)\bDisableDeleteNotify\s*=\s*([01])").unwrap();
        for cap in fallback.captures_iter(text) {
            let value = cap
                .get(1)
                .and_then(|m| m.as_str().parse::<u32>().ok())
                .unwrap_or(0);
            out.push(("global".to_string(), value));
        }
    }

    out
}

fn collect_trim_set_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_trim_set_command(&normalized) {
                continue;
            }
            hits.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220)
            ));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn looks_like_trim_set_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    if !normalized.contains("disabledeletenotify") {
        return false;
    }

    // fsutil behavior set DisableDeleteNotify 1
    if normalized.contains("fsutil") && normalized.contains("set") {
        let set_re = Regex::new(r"(?i)disabledeletenotify[^\r\n]*\b1\b").unwrap();
        return set_re.is_match(&normalized);
    }

    false
}

fn collect_trim_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains("defrag")
            || normalized.contains("optimize drives")
            || normalized.contains("disabledeletenotify")
            || normalized.contains("storport")
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

fn query_physical_media_types() -> Vec<String> {
    let script = "Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName,MediaType,BusType | ConvertTo-Json -Compress";
    let Some(raw) = run_powershell(script) else {
        return Vec::new();
    };
    let text = raw.trim();
    if text.is_empty() {
        return Vec::new();
    }

    let parse_item = |item: &Value| -> Option<String> {
        let name = item
            .get("FriendlyName")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let media = item
            .get("MediaType")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let bus = item
            .get("BusType")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        Some(format!("{name} media={media} bus={bus}"))
    };

    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => items.iter().filter_map(parse_item).collect(),
        Ok(item) => parse_item(&item).into_iter().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{looks_like_trim_set_command, parse_disable_delete_notify};

    #[test]
    fn parse_disable_notify_supports_modern_and_legacy_output() {
        let modern =
            "NTFS DisableDeleteNotify = 1 (Disabled)\nReFS DisableDeleteNotify = 0 (Enabled)";
        let parsed = parse_disable_delete_notify(modern);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|(k, v)| k == "NTFS" && *v == 1));
        assert!(parsed.iter().any(|(k, v)| k == "ReFS" && *v == 0));

        let legacy = "DisableDeleteNotify = 1";
        let parsed_legacy = parse_disable_delete_notify(legacy);
        assert_eq!(parsed_legacy, vec![("global".to_string(), 1)]);
    }

    #[test]
    fn trim_command_matcher_requires_disabledeletenotify_set_to_one() {
        assert!(looks_like_trim_set_command(
            "fsutil behavior set DisableDeleteNotify 1"
        ));
        assert!(!looks_like_trim_set_command(
            "fsutil behavior set DisableDeleteNotify 0"
        ));
    }
}
