use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, prefetch_file_names_by_prefixes, query_event_records,
    truncate_text,
};

const CLOUD_PREFIXES: &[&str] = &[
    "RCLONE.EXE-",
    "MEGACMD.EXE-",
    "ONEDRIVE.EXE-",
    "DROPBOX.EXE-",
    "GOOGLEDRIVEFS.EXE-",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        34,
        "bypass34_cloud_sync_delete",
        "Cloud sync auto-delete traces",
        "No high-confidence cloud sync delete/purge command evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 340);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 260);
    let command_hits = collect_cloud_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let sysmon_delete_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[23, 26], 420);
    let delete_hits = collect_cloud_delete_hits(&sysmon_delete_events);

    let prefetch = prefetch_file_names_by_prefixes(CLOUD_PREFIXES);

    let destructive_count = command_hits
        .iter()
        .filter(|h| h.kind == CloudCommandKind::Destructive)
        .count();
    let reset_or_unlink_count = command_hits
        .iter()
        .filter(|h| h.kind == CloudCommandKind::ResetOrUnlink)
        .count();

    if destructive_count >= 1 && !delete_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Cloud destructive command traces correlate with cloud-path file deletion telemetry."
                .to_string();
    } else if destructive_count >= 1 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit cloud-sync destructive command traces (delete/purge/remove)."
                .to_string();
    } else if delete_hits.len() >= 15 && !prefetch.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "High volume cloud-path deletion telemetry with cloud-client execution traces."
                .to_string();
    } else if reset_or_unlink_count > 0 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Cloud-client reset/unlink command traces observed; review for potential artifact suppression."
                .to_string();
    } else if !delete_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Cloud-path deletion telemetry observed (weak single indicator).".to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} cloud-sync command trace(s)", command_hits.len()),
            details: command_hits
                .iter()
                .map(|hit| hit.line.clone())
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !delete_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 23/26".to_string(),
            summary: format!("{} cloud-path deletion event(s)", delete_hits.len()),
            details: delete_hits.join("; "),
        });
    }

    if !prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} cloud-client prefetch file(s)", prefetch.len()),
            details: prefetch.join("; "),
        });
    }

    logger.log(
        "bypass34_cloud_sync_delete",
        "info",
        "cloud sync checks complete",
        serde_json::json!({
            "destructive_commands": destructive_count,
            "reset_or_unlink_commands": reset_or_unlink_count,
            "delete_hits": delete_hits.len(),
            "prefetch": prefetch.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudCommandKind {
    Destructive,
    ResetOrUnlink,
}

#[derive(Debug, Clone)]
struct CloudCommandHit {
    kind: CloudCommandKind,
    line: String,
}

fn collect_cloud_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<CloudCommandHit> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            let kind = classify_cloud_command(&normalized);
            let Some(kind) = kind else {
                continue;
            };
            hits.push(CloudCommandHit {
                kind,
                line: format!(
                    "{} | {} Event {} | {}",
                    event.time_created,
                    source,
                    event.event_id,
                    truncate_text(&event.message, 220)
                ),
            });
        }
    }

    hits.sort_by(|a, b| a.line.cmp(&b.line));
    hits.dedup_by(|a, b| a.kind == b.kind && a.line == b.line);
    hits
}

fn classify_cloud_command(text: &str) -> Option<CloudCommandKind> {
    let normalized = text.to_lowercase();

    let rclone_destructive = normalized.contains("rclone")
        && (normalized.contains(" delete ")
            || normalized.contains(" purge ")
            || (normalized.contains(" sync ") && normalized.contains("--delete"))
            || normalized.contains("--delete-during")
            || normalized.contains("--delete-before"));
    let mega_destructive = (normalized.contains("megacmd")
        || normalized.contains("mega-rm")
        || normalized.contains("mega rm"))
        && (normalized.contains(" rm ")
            || normalized.contains(" delete ")
            || normalized.contains("purge"));
    let dropbox_or_drive_destructive = (normalized.contains("dropbox")
        || normalized.contains("googledrive")
        || normalized.contains("gdrive"))
        && (normalized.contains("delete")
            || normalized.contains("remove")
            || normalized.contains("purge"));

    if rclone_destructive || mega_destructive || dropbox_or_drive_destructive {
        return Some(CloudCommandKind::Destructive);
    }

    let reset_or_unlink = (normalized.contains("onedrive")
        && (normalized.contains("/reset") || normalized.contains("/shutdown")))
        || (normalized.contains("dropbox") && normalized.contains("unlink"));

    if reset_or_unlink {
        return Some(CloudCommandKind::ResetOrUnlink);
    }

    None
}

fn collect_cloud_delete_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();

    for event in events {
        let target = extract_event_data_value(&event.raw_xml, "TargetFilename")
            .or_else(|| extract_event_data_value(&event.raw_xml, "TargetFileName"))
            .unwrap_or_else(|| event.message.clone());
        let t = target.to_lowercase();

        if !(t.contains("onedrive")
            || t.contains("dropbox")
            || t.contains("googledrive")
            || t.contains("google drive")
            || t.contains("megasync")
            || t.contains("\\rclone\\"))
        {
            continue;
        }

        out.push(format!(
            "{} | Event {} | {}",
            event.time_created,
            event.event_id,
            truncate_text(&target, 220)
        ));
    }

    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::{CloudCommandKind, classify_cloud_command};

    #[test]
    fn cloud_command_classifier_marks_destructive_and_reset() {
        assert_eq!(
            classify_cloud_command("rclone purge remote:folder"),
            Some(CloudCommandKind::Destructive)
        );
        assert_eq!(
            classify_cloud_command("OneDrive.exe /reset"),
            Some(CloudCommandKind::ResetOrUnlink)
        );
        assert_eq!(classify_cloud_command("rclone ls remote:"), None);
    }
}
