use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, prefetch_file_names_by_prefixes, query_event_records,
    truncate_text,
};

const EXIF_PREFIXES: &[&str] = &["EXIFTOOL.EXE-", "JHEAD.EXE-", "MAT2.EXE-"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        35,
        "bypass35_exif_timestamp_edit",
        "EXIF timestamp editing",
        "No explicit EXIF timestamp-manipulation command evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_exif_edit_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let sysmon_time_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[2], 260);
    let time_change_hits = collect_exif_time_change_hits(&sysmon_time_events);
    let prefetch = prefetch_file_names_by_prefixes(EXIF_PREFIXES);

    if !command_hits.is_empty() && !time_change_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "EXIF timestamp rewrite commands correlate with image-file timestamp change telemetry."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected explicit EXIF timestamp rewrite command traces.".to_string();
    } else if !time_change_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Image timestamp-change telemetry found with EXIF tooling indicators in process history."
                .to_string();
    } else if !prefetch.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "EXIF metadata tooling execution artifacts found; review for timestamp rewriting."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} EXIF timestamp edit command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !time_change_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 2".to_string(),
            summary: format!("{} image timestamp change event(s)", time_change_hits.len()),
            details: time_change_hits.join("; "),
        });
    }

    if !prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} EXIF tool prefetch file(s)", prefetch.len()),
            details: prefetch.join("; "),
        });
    }

    logger.log(
        "bypass35_exif_timestamp_edit",
        "info",
        "exif checks complete",
        serde_json::json!({
            "cmd_hits": command_hits.len(),
            "time_change_hits": time_change_hits.len(),
            "prefetch": prefetch.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_exif_edit_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_exif_timestamp_edit_command(&normalized) {
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

fn looks_like_exif_timestamp_edit_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let has_tool = normalized.contains("exiftool")
        || normalized.contains("jhead")
        || normalized.contains("mat2");
    if !has_tool {
        return false;
    }

    normalized.contains("-alldates=")
        || normalized.contains("-datetimeoriginal=")
        || normalized.contains("-modifydate=")
        || normalized.contains("-createdate=")
        || normalized.contains("-filemodifydate=")
        || normalized.contains("-filecreatedate=")
        || normalized.contains("-ft")
}

fn collect_exif_time_change_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();

    for event in events {
        let target = extract_event_data_value(&event.raw_xml, "TargetFilename")
            .or_else(|| extract_event_data_value(&event.raw_xml, "TargetFileName"))
            .unwrap_or_else(|| event.message.clone());
        if !is_media_path(&target) {
            continue;
        }

        let process = extract_event_data_value(&event.raw_xml, "Image")
            .or_else(|| extract_event_data_value(&event.raw_xml, "ProcessGuid"))
            .unwrap_or_default();
        let process_l = process.to_lowercase();
        if !(process_l.contains("exiftool")
            || process_l.contains("jhead")
            || process_l.contains("powershell")
            || process_l.contains("cmd.exe"))
        {
            continue;
        }

        out.push(format!(
            "{} | Event {} | target={} process={}",
            event.time_created,
            event.event_id,
            truncate_text(&target, 140),
            truncate_text(&process, 100)
        ));
    }

    out.sort();
    out.dedup();
    out
}

fn is_media_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".png")
        || lower.ends_with(".gif")
        || lower.ends_with(".heic")
        || lower.ends_with(".tif")
        || lower.ends_with(".tiff")
        || lower.ends_with(".mp4")
        || lower.ends_with(".mov")
}

#[cfg(test)]
mod tests {
    use super::{is_media_path, looks_like_exif_timestamp_edit_command};

    #[test]
    fn exif_command_matcher_finds_date_rewrite_flags() {
        assert!(looks_like_exif_timestamp_edit_command(
            "exiftool -AllDates=2020:01:01 10:00:00 photo.jpg"
        ));
        assert!(looks_like_exif_timestamp_edit_command(
            "jhead -ft photo.jpg"
        ));
        assert!(!looks_like_exif_timestamp_edit_command("exiftool -ver"));
    }

    #[test]
    fn media_path_matcher_handles_common_extensions() {
        assert!(is_media_path("C:\\x\\photo.JPG"));
        assert!(is_media_path("C:\\x\\clip.mov"));
        assert!(!is_media_path("C:\\x\\doc.txt"));
    }
}
