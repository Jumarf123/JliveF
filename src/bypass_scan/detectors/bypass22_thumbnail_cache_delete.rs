use std::fs;
use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

const EXPLORER_ADVANCED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const THUMBCACHE_TARGET: &str = "thumbcache";
const THUMBCACHE_COMMAND_MARKERS: &[&str] = &[
    "remove-item",
    "del ",
    "erase ",
    "rd /s /q",
    "rmdir /s /q",
    "cleanmgr",
    "storagesense",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        22,
        "bypass22_thumbnail_cache_delete",
        "Thumbnail cache deletion",
        "No high-confidence thumbnail-cache wipe evidence found.",
    );

    let thumb_dir = thumbcache_dir();
    let thumb_inventory = inspect_thumbcache_inventory(&thumb_dir);
    let disable_thumbnail_cache = read_disable_thumbnail_cache();

    let sysmon_delete_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[23, 26], 260);
    let delete_hits = collect_thumbcache_delete_hits(&sysmon_delete_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 280);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_thumbcache_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    if delete_hits.len() >= 5 && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Thumbnail cache delete telemetry correlates with explicit wipe command traces."
                .to_string();
    } else if delete_hits.len() >= 5 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Repeated thumbnail-cache deletion events found without direct command attribution."
                .to_string();
    } else if !command_hits.is_empty()
        && thumb_inventory.thumbcache_count == 0
        && disable_thumbnail_cache != Some(1)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Thumbcache wipe commands detected while thumbcache artifacts are absent.".to_string();
    } else if thumb_inventory.dir_exists
        && thumb_inventory.dir_readable
        && thumb_inventory.thumbcache_count == 0
        && disable_thumbnail_cache != Some(1)
        && !delete_hits.is_empty()
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Thumbcache artifacts are absent with matching delete telemetry.".to_string();
    }

    if !delete_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 23/26".to_string(),
            summary: format!("{} thumbcache delete event(s)", delete_hits.len()),
            details: delete_hits.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} thumbcache wipe command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: thumb_dir.display().to_string(),
        summary: format!(
            "dir_exists={} dir_readable={} thumbcache_count={} latest_write={}",
            thumb_inventory.dir_exists,
            thumb_inventory.dir_readable,
            thumb_inventory.thumbcache_count,
            thumb_inventory
                .latest_thumb_write
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: String::new(),
    });

    result.evidence.push(EvidenceItem {
        source: format!(r"HKCU\{}\DisableThumbnailCache", EXPLORER_ADVANCED),
        summary: format!(
            "DisableThumbnailCache={}",
            disable_thumbnail_cache
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details:
            "If set to 1, low/absent thumbcache is expected and should not be treated as strong anti-forensic evidence."
                .to_string(),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate with adjacent browser/cache cleanup activity and process lineage before final attribution."
                .to_string(),
        );
    }

    logger.log(
        "bypass22_thumbnail_cache_delete",
        "info",
        "thumbnail cache check complete",
        serde_json::json!({
            "thumb_count": thumb_inventory.thumbcache_count,
            "dir_exists": thumb_inventory.dir_exists,
            "dir_readable": thumb_inventory.dir_readable,
            "delete_hits": delete_hits.len(),
            "command_hits": command_hits.len(),
            "disable_thumbnail_cache": disable_thumbnail_cache,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn thumbcache_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default\AppData\Local"))
        .join("Microsoft\\Windows\\Explorer")
}

#[derive(Debug, Clone)]
struct ThumbcacheInventory {
    dir_exists: bool,
    dir_readable: bool,
    thumbcache_count: usize,
    latest_thumb_write: Option<String>,
}

fn inspect_thumbcache_inventory(dir: &PathBuf) -> ThumbcacheInventory {
    let dir_exists = dir.exists();
    let Ok(entries) = fs::read_dir(dir) else {
        return ThumbcacheInventory {
            dir_exists,
            dir_readable: false,
            thumbcache_count: 0,
            latest_thumb_write: None,
        };
    };

    let mut thumbcache_count = 0usize;
    let mut latest: Option<std::time::SystemTime> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if !name.starts_with("thumbcache") {
            continue;
        }
        thumbcache_count += 1;
        let modified = match entry.metadata().ok().and_then(|m| m.modified().ok()) {
            Some(value) => value,
            None => continue,
        };
        latest = Some(match latest {
            Some(current) if current > modified => current,
            _ => modified,
        });
    }

    ThumbcacheInventory {
        dir_exists,
        dir_readable: true,
        thumbcache_count,
        latest_thumb_write: latest.map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
    }
}

fn read_disable_thumbnail_cache() -> Option<u32> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(EXPLORER_ADVANCED, KEY_READ)
        .ok()?;
    key.get_value::<u32, _>("DisableThumbnailCache").ok()
}

fn collect_thumbcache_delete_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if !normalized.contains(THUMBCACHE_TARGET) {
            continue;
        }
        if !normalized.contains("delete") && !normalized.contains("removed") {
            continue;
        }
        out.push(format!(
            "{} | Event {} | {}",
            event.time_created,
            event.event_id,
            truncate_text(&event.message, 200),
        ));
    }
    out
}

fn collect_thumbcache_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_thumbcache_wipe_command(&normalized) {
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

fn looks_like_thumbcache_wipe_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    normalized.contains(THUMBCACHE_TARGET)
        && THUMBCACHE_COMMAND_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::looks_like_thumbcache_wipe_command;

    #[test]
    fn thumbcache_command_matcher_requires_target_and_action() {
        assert!(looks_like_thumbcache_wipe_command(
            "powershell Remove-Item $env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer\\thumbcache_*.db -Force"
        ));
        assert!(!looks_like_thumbcache_wipe_command(
            "Get-ChildItem $env:LOCALAPPDATA\\Microsoft\\Windows\\Explorer"
        ));
    }
}
