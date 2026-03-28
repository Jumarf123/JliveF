use std::fs;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, prefetch_dir, query_event_records, truncate_text,
};

const WIPE_TOOLS: &[&str] = &["SDELETE.EXE-", "CIPHER.EXE-", "SHRED.EXE-"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        16,
        "bypass16_file_wiping",
        "File wiping tool execution",
        "No strong wiping-tool evidence found.",
    );

    let prefetch_hits = collect_wipe_tool_prefetch_hits();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        240,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_wipe_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let sysmon_delete_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[23, 26], 420);
    let delete_hits = collect_wipe_delete_hits(&sysmon_delete_events);

    if !prefetch_hits.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Wiping-tool execution evidence present in Prefetch and command telemetry.".to_string();
    } else if !command_hits.is_empty() && !delete_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Wiping commands correlate with Sysmon file-deletion telemetry.".to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary = "Detected explicit wiping command traces.".to_string();
    } else if !prefetch_hits.is_empty() || !delete_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Single wiping indicator detected (Prefetch or deletion telemetry).".to_string();
    }

    if !prefetch_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} wipe-tool prefetch file(s)", prefetch_hits.len()),
            details: prefetch_hits.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} wipe command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !delete_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 23/26".to_string(),
            summary: format!("{} wipe-like deletion event(s)", delete_hits.len()),
            details: delete_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate with USN/$LogFile timeline and restored shadow copies to scope deleted evidence."
                .to_string(),
        );
    }

    logger.log(
        "bypass16_file_wiping",
        "info",
        "wiping tool check complete",
        serde_json::json!({
            "prefetch_hits": prefetch_hits.len(),
            "command_hits": command_hits.len(),
            "delete_hits": delete_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_wipe_tool_prefetch_hits() -> Vec<String> {
    let dir = prefetch_dir();
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if WIPE_TOOLS
            .iter()
            .any(|prefix| name.to_ascii_uppercase().starts_with(prefix))
        {
            let modified = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string());
            hits.push(format!("{name} (modified {modified})"));
        }
    }
    hits.sort();
    hits
}

fn collect_wipe_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_wipe_command(&text) {
                continue;
            }
            out.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220)
            ));
        }
    }

    out.sort();
    out.dedup();
    out
}

fn looks_like_wipe_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    (normalized.contains("sdelete")
        && (normalized.contains(" -p ")
            || normalized.contains(" -z")
            || normalized.contains(" -c")
            || normalized.contains(" -s ")))
        || (normalized.contains("cipher") && normalized.contains(" /w:"))
        || (normalized.contains("shred")
            && (normalized.contains(" -u")
                || normalized.contains(" --remove")
                || normalized.contains(" --iterations")))
}

fn collect_wipe_delete_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();

    for event in events {
        let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        let image = extract_event_data_value(&event.raw_xml, "Image")
            .or_else(|| extract_event_data_value(&event.raw_xml, "ProcessName"))
            .unwrap_or_default()
            .to_lowercase();

        if !(image.contains("sdelete")
            || image.contains("cipher")
            || image.contains("shred")
            || text.contains("sdelete")
            || text.contains("cipher")
            || text.contains("shred"))
        {
            continue;
        }

        let target = extract_event_data_value(&event.raw_xml, "TargetFilename")
            .or_else(|| extract_event_data_value(&event.raw_xml, "TargetFileName"))
            .unwrap_or_else(|| event.message.clone());

        out.push(format!(
            "{} | Event {} | image={} target={}",
            event.time_created,
            event.event_id,
            truncate_text(&image, 80),
            truncate_text(&target, 120)
        ));
    }

    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::looks_like_wipe_command;

    #[test]
    fn wipe_command_matcher_detects_sdelete_and_cipher() {
        assert!(looks_like_wipe_command("sdelete -p 3 C:\\test.txt"));
        assert!(looks_like_wipe_command("cipher /w:C:\\Temp"));
        assert!(!looks_like_wipe_command("del C:\\test.txt"));
    }
}
