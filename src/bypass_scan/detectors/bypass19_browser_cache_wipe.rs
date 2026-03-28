use std::fs;
use std::path::PathBuf;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, truncate_text,
};

const CLEANER_PREFIXES: &[&str] = &[
    "CCLEANER.EXE-",
    "BLEACHBIT.EXE-",
    "PRIVAZER.EXE-",
    "WISEDISKCLEANER.EXE-",
];

const CLEANER_TOOL_NAMES: &[&str] = &["ccleaner", "bleachbit", "privazer", "wisediskcleaner"];

const BROWSER_TARGET_MARKERS: &[&str] = &[
    r"\google\chrome\user data",
    r"\microsoft\edge\user data",
    r"\mozilla\firefox\profiles",
];

const WIPE_ACTION_MARKERS: &[&str] = &[
    "remove-item",
    "del ",
    "erase ",
    "rd /s /q",
    "rmdir /s /q",
    "sdelete",
    "cipher /w",
];

#[derive(Debug, Clone)]
struct ArtifactState {
    browser: String,
    path: PathBuf,
    exists: bool,
    size: Option<u64>,
    modified_utc: Option<String>,
}

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        19,
        "bypass19_browser_cache_wipe",
        "Browser cache/history wipe",
        "No high-confidence browser wipe evidence found. Missing browser files alone are treated as non-actionable.",
    );

    let cleaner_prefetch = prefetch_file_names_by_prefixes(CLEANER_PREFIXES);
    let artifact_states = collect_browser_artifact_states();

    let sysmon_delete_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[23, 26], 320);
    let browser_delete_hits = collect_browser_delete_hits(&sysmon_delete_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        300,
    );
    let sec_events = query_event_records("Security", &[4688], 380);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 280);

    let command_hits = collect_browser_wipe_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);
    let cleaner_command_hits = collect_cleaner_tool_execution_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let missing_history_count = artifact_states.iter().filter(|s| !s.exists).count();

    if browser_delete_hits.len() >= 6 && (!cleaner_prefetch.is_empty() || !command_hits.is_empty())
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Browser profile deletion telemetry correlates with cleaner/wipe execution traces."
                .to_string();
    } else if !command_hits.is_empty()
        && (!cleaner_prefetch.is_empty() || !cleaner_command_hits.is_empty())
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit browser-wipe commands with independent cleaner execution evidence."
                .to_string();
    } else if browser_delete_hits.len() >= 2 || !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Found browser artifact wipe indicators; correlation is present but not conclusive."
                .to_string();
    } else if !cleaner_prefetch.is_empty() && missing_history_count >= 2 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Cleaner execution traces exist and multiple browser history artifacts are missing."
                .to_string();
    }

    if !browser_delete_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 23/26".to_string(),
            summary: format!(
                "{} browser profile delete event(s)",
                browser_delete_hits.len()
            ),
            details: browser_delete_hits.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} browser wipe command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !cleaner_command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process execution telemetry".to_string(),
            summary: format!(
                "{} cleaner tool execution trace(s)",
                cleaner_command_hits.len()
            ),
            details: cleaner_command_hits.join("; "),
        });
    }

    if !cleaner_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} cleaner prefetch file(s)", cleaner_prefetch.len()),
            details: cleaner_prefetch.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Browser history artifact state".to_string(),
        summary: format!(
            "{} artifact(s) checked, missing={}",
            artifact_states.len(),
            missing_history_count
        ),
        details: artifact_states
            .iter()
            .map(|state| {
                format!(
                    "{} | state={} size={} modified={} path={}",
                    state.browser,
                    if state.exists { "present" } else { "missing" },
                    state
                        .size
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    state
                        .modified_utc
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    state.path.display()
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
    });

    result.evidence.push(EvidenceItem {
        source: "Interpretation note".to_string(),
        summary: "Missing Edge/Firefox profile artifacts can be normal when browser/profile is not installed or not used recently.".to_string(),
        details: "Detection requires command/process or delete telemetry correlation, not just missing files."
            .to_string(),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate browser wipe signals with download/network telemetry (DNS/Proxy/EDR) to recover cleaned activity."
                .to_string(),
        );
        result.recommendations.push(
            "If Sysmon is not deployed, prioritize command-line auditing and centralized event forwarding for future detections."
                .to_string(),
        );
    }

    logger.log(
        "bypass19_browser_cache_wipe",
        "info",
        "browser wipe check complete",
        serde_json::json!({
            "cleaner_prefetch": cleaner_prefetch.len(),
            "browser_delete_hits": browser_delete_hits.len(),
            "command_hits": command_hits.len(),
            "cleaner_command_hits": cleaner_command_hits.len(),
            "missing_history_count": missing_history_count,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_browser_artifact_states() -> Vec<ArtifactState> {
    let mut states = Vec::new();
    let local_app_data = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from);
    let roaming_app_data = std::env::var("APPDATA").ok().map(PathBuf::from);

    if let Some(local) = &local_app_data {
        states.push(read_artifact_state(
            "Chrome/History",
            local.join(r"Google\Chrome\User Data\Default\History"),
        ));
        states.push(read_artifact_state(
            "Chrome/Cookies",
            local.join(r"Google\Chrome\User Data\Default\Network\Cookies"),
        ));
        states.push(read_artifact_state(
            "Edge/History",
            local.join(r"Microsoft\Edge\User Data\Default\History"),
        ));
        states.push(read_artifact_state(
            "Edge/Cookies",
            local.join(r"Microsoft\Edge\User Data\Default\Network\Cookies"),
        ));
    }

    if let Some(roaming) = &roaming_app_data {
        let ff_profiles = roaming.join(r"Mozilla\Firefox\Profiles");
        if let Ok(entries) = fs::read_dir(ff_profiles) {
            for entry in entries.flatten().take(4) {
                let profile_path = entry.path();
                if !profile_path.is_dir() {
                    continue;
                }
                let profile_name = profile_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                states.push(read_artifact_state(
                    &format!("Firefox/{profile_name}/places.sqlite"),
                    profile_path.join("places.sqlite"),
                ));
                states.push(read_artifact_state(
                    &format!("Firefox/{profile_name}/cookies.sqlite"),
                    profile_path.join("cookies.sqlite"),
                ));
            }
        }
    }

    states
}

fn read_artifact_state(browser: &str, path: PathBuf) -> ArtifactState {
    let metadata = fs::metadata(&path).ok();
    let exists = metadata.is_some();
    let size = metadata.as_ref().map(|m| m.len());
    let modified_utc = metadata
        .and_then(|m| m.modified().ok())
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

    ArtifactState {
        browser: browser.to_string(),
        path,
        exists,
        size,
        modified_utc,
    }
}

fn collect_browser_delete_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();

    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if !contains_browser_target(&normalized) {
            continue;
        }
        if !normalized.contains("delete") && !normalized.contains("removed") {
            continue;
        }

        hits.push(format!(
            "{} | Event {} | {}",
            event.time_created,
            event.event_id,
            truncate_text(&event.message, 200),
        ));
    }

    hits
}

fn collect_browser_wipe_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_browser_wipe_command(&normalized) {
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

fn collect_cleaner_tool_execution_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !CLEANER_TOOL_NAMES
                .iter()
                .any(|needle| normalized.contains(needle))
            {
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

fn looks_like_browser_wipe_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    contains_browser_target(&normalized)
        && WIPE_ACTION_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
}

fn contains_browser_target(text: &str) -> bool {
    BROWSER_TARGET_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{contains_browser_target, looks_like_browser_wipe_command};

    #[test]
    fn browser_wipe_matcher_requires_target_and_action() {
        assert!(looks_like_browser_wipe_command(
            "powershell remove-item C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache -Recurse -Force"
        ));
        assert!(!looks_like_browser_wipe_command(
            "powershell get-childitem C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data"
        ));
    }

    #[test]
    fn browser_target_detector_matches_known_profiles() {
        assert!(contains_browser_target(
            "c:\\users\\u\\appdata\\roaming\\mozilla\\firefox\\profiles\\x.default\\places.sqlite"
        ));
        assert!(!contains_browser_target("c:\\temp\\notes.txt"));
    }
}
