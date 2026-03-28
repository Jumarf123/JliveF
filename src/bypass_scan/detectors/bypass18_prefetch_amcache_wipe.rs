use std::fs;
use std::path::Path;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_dir, query_event_records, run_command, truncate_text,
};

const PREFETCH_WIPE_ACTION_NEEDLES: &[&str] =
    &["remove-item", "del /f", "erase ", "sdelete", "cipher /w"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        18,
        "bypass18_prefetch_amcache_wipe",
        "Prefetch/Amcache wiping",
        "No strong evidence of Prefetch/Amcache mass deletion.",
    );

    let prefetch_count = count_prefetch_files();
    let prefetch_last_write = newest_prefetch_write_time();
    let prefetcher_setting = query_enable_prefetcher();
    let amcache_path = Path::new(r"C:\Windows\AppCompat\Programs\Amcache.hve");
    let amcache_exists = amcache_path.exists();
    let amcache_size = fs::metadata(amcache_path).map(|m| m.len()).ok();

    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[23, 26], 260);
    let sysmon_delete_hits = collect_sysmon_delete_hits(&sysmon_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 340);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let command_hits = collect_wipe_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let prefetch_disabled = prefetcher_setting == Some(0);

    if sysmon_delete_hits.len() >= 3 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Sysmon shows repeated Prefetch/Amcache deletion activity.".to_string();
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 23/26".to_string(),
            summary: format!("{} deletion event(s)", sysmon_delete_hits.len()),
            details: sysmon_delete_hits.join("; "),
        });
        if !command_hits.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!("{} wipe command trace(s)", command_hits.len()),
                details: command_hits.join("; "),
            });
        }
    } else if !command_hits.is_empty() && !prefetch_disabled && prefetch_count < 20 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Wipe command traces found with unusually low Prefetch population.".to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} wipe command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if !amcache_exists || (!prefetch_disabled && prefetch_count < 10) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Prefetch/Amcache artifacts are sparse or missing without direct delete telemetry."
                .to_string();
    }

    result.evidence.push(EvidenceItem {
        source: r"C:\Windows\Prefetch".to_string(),
        summary: format!(
            "prefetch_count={} prefetch_disabled={} enable_prefetcher={}",
            prefetch_count,
            prefetch_disabled,
            prefetcher_setting
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: prefetch_last_write.unwrap_or_else(|| "no .pf files found".to_string()),
    });

    result.evidence.push(EvidenceItem {
        source: amcache_path.display().to_string(),
        summary: format!(
            "exists={} size={}",
            amcache_exists,
            amcache_size
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: String::new(),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate wipe indicators with execution artifacts and adjacent anti-forensic actions (log clear/browser wipe).".to_string(),
        );
        result.recommendations.push(
            "Check whether Prefetch is intentionally disabled by policy before final attribution."
                .to_string(),
        );
    }

    logger.log(
        "bypass18_prefetch_amcache_wipe",
        "info",
        "prefetch/amcache wipe check complete",
        serde_json::json!({
            "prefetch_count": prefetch_count,
            "prefetcher_setting": prefetcher_setting,
            "amcache_exists": amcache_exists,
            "sysmon_delete_hits": sysmon_delete_hits.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn count_prefetch_files() -> usize {
    let Ok(entries) = fs::read_dir(prefetch_dir()) else {
        return 0;
    };

    entries
        .flatten()
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("pf"))
                .unwrap_or(false)
        })
        .count()
}

fn newest_prefetch_write_time() -> Option<String> {
    let entries = fs::read_dir(prefetch_dir()).ok()?;
    let mut latest: Option<std::time::SystemTime> = None;

    for entry in entries.flatten() {
        let is_pf = entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("pf"))
            .unwrap_or(false);
        if !is_pf {
            continue;
        }
        let modified = match entry.metadata().ok().and_then(|m| m.modified().ok()) {
            Some(value) => value,
            None => continue,
        };
        latest = Some(match latest {
            Some(current) if current > modified => current,
            _ => modified,
        });
    }

    latest.map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
}

fn collect_sysmon_delete_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains(r"\windows\prefetch\") || normalized.contains("amcache.hve") {
            hits.push(format!(
                "{} | Event {} | {}",
                event.time_created,
                event.event_id,
                truncate_text(&event.message, 200),
            ));
        }
    }
    hits
}

fn collect_wipe_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_prefetch_wipe_command(&normalized) {
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

fn looks_like_prefetch_wipe_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target_hit =
        normalized.contains(r"\windows\prefetch\") || normalized.contains("amcache.hve");
    let action_hit = PREFETCH_WIPE_ACTION_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle));

    target_hit && action_hit
}

fn query_enable_prefetcher() -> Option<u32> {
    let output = run_command(
        "reg",
        &[
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            "/v",
            "EnablePrefetcher",
        ],
    )?;
    let re = regex::Regex::new(r"(?i)EnablePrefetcher\s+REG_DWORD\s+0x([0-9a-f]+)").ok()?;
    let captures = re.captures(&output)?;
    let hex = captures.get(1)?.as_str();
    u32::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::looks_like_prefetch_wipe_command;

    #[test]
    fn command_matcher_detects_prefetch_wipe_patterns() {
        assert!(looks_like_prefetch_wipe_command(
            "powershell remove-item C:\\Windows\\Prefetch\\*.pf -Force"
        ));
        assert!(looks_like_prefetch_wipe_command(
            "cmd /c del /f /q C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
        ));
        assert!(!looks_like_prefetch_wipe_command(
            "cmd /c dir C:\\Windows\\Prefetch"
        ));
    }
}
