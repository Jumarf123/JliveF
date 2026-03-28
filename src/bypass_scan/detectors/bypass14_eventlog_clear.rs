use chrono::{DateTime, Duration, Utc};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventLogState, EventRecord, extract_event_data_value, extract_xml_tag_value,
    query_event_log_states, query_event_records, truncate_text,
};

const CLEAR_COMMAND_NEEDLES: &[&str] = &[
    "wevtutil cl ",
    "wevtutil clear-log",
    "clear-eventlog",
    "remove-eventlog",
    "limit-eventlog",
    "clear-winevent",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        14,
        "bypass14_eventlog_clear",
        "Event log clearing",
        "No EventLog clear evidence found in queried channels.",
    );

    let sec_1102 = query_event_records("Security", &[1102], 120);
    let sys_104 = query_event_records("System", &[104], 120);
    let sec_1100 = query_event_records("Security", &[1100], 80);
    let ps_4104 = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        280,
    );
    let sec_4688 = query_event_records("Security", &[4688], 360);
    let sysmon_1 = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 280);

    let command_hits = collect_clear_command_hits(&[
        ("PowerShell/Operational", &ps_4104),
        ("Security", &sec_4688),
        ("Sysmon/Operational", &sysmon_1),
    ]);

    let log_states = query_event_log_states(&[
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
    ]);
    let suspicious_states = collect_suspicious_log_states(&log_states);

    let has_explicit_clear = !sec_1102.is_empty() || !sys_104.is_empty();
    let has_command_evidence = !command_hits.is_empty();
    let has_shutdown_context = !sec_1100.is_empty();

    if has_explicit_clear {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit Event Log clear events (Security 1102 and/or System 104)."
                .to_string();

        if !sec_1102.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "Security EventID 1102".to_string(),
                summary: format!("{} security log clear event(s)", sec_1102.len()),
                details: sec_1102
                    .iter()
                    .map(format_1102_event)
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        if !sys_104.is_empty() {
            result.evidence.push(EvidenceItem {
                source: "System EventID 104".to_string(),
                summary: format!("{} system log clear event(s)", sys_104.len()),
                details: sys_104
                    .iter()
                    .map(format_104_event)
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        if has_command_evidence {
            result.evidence.push(EvidenceItem {
                source: "Process/Script command telemetry".to_string(),
                summary: format!("{} clear command trace(s)", command_hits.len()),
                details: command_hits.join("; "),
            });
        }
    } else if has_command_evidence && (has_shutdown_context || !suspicious_states.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected Event Log clear command traces with supporting service/log-state anomalies."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} clear command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if has_command_evidence {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Found clear-log commands, but no direct 1102/104 confirmation in current window."
                .to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} clear command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if has_shutdown_context || !suspicious_states.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary = "Detected event-log channel anomalies without direct clear commands. This may be policy hardening or tampering and requires baseline validation.".to_string();
    }

    if has_shutdown_context {
        result.evidence.push(EvidenceItem {
            source: "Security EventID 1100".to_string(),
            summary: format!("{} event logging service shutdown event(s)", sec_1100.len()),
            details: sec_1100
                .iter()
                .map(|e| format!("{} | {}", e.time_created, truncate_text(&e.message, 180)))
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !suspicious_states.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Event log channel metadata".to_string(),
            summary: format!("{} suspicious channel state(s)", suspicious_states.len()),
            details: suspicious_states.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate event timestamps with process execution (wevtutil/Clear-EventLog) and preserve centralized copies (WEF/SIEM).".to_string(),
        );
        result.recommendations.push(
            "Validate if maintenance tooling could explain command traces before final attribution."
                .to_string(),
        );
    }

    logger.log(
        "bypass14_eventlog_clear",
        "info",
        "event log clear check complete",
        serde_json::json!({
            "event_1102": sec_1102.len(),
            "event_104": sys_104.len(),
            "event_1100": sec_1100.len(),
            "command_hits": command_hits.len(),
            "suspicious_log_states": suspicious_states.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn format_1102_event(event: &EventRecord) -> String {
    let username = extract_event_data_value(&event.raw_xml, "SubjectUserName")
        .or_else(|| extract_xml_tag_value(&event.raw_xml, "SubjectUserName"))
        .unwrap_or_else(|| "unknown_user".to_string());
    let domain = extract_event_data_value(&event.raw_xml, "SubjectDomainName")
        .or_else(|| extract_xml_tag_value(&event.raw_xml, "SubjectDomainName"))
        .unwrap_or_else(|| "unknown_domain".to_string());
    let sid = extract_event_data_value(&event.raw_xml, "SubjectUserSid")
        .or_else(|| extract_xml_tag_value(&event.raw_xml, "SubjectUserSid"))
        .unwrap_or_else(|| "unknown_sid".to_string());

    format!(
        "{} | {}\\{} | SID={} | {}",
        event.time_created,
        domain,
        username,
        sid,
        truncate_text(&event.message, 220),
    )
}

fn format_104_event(event: &EventRecord) -> String {
    let log_file = extract_event_data_value(&event.raw_xml, "param1")
        .or_else(|| extract_xml_tag_value(&event.raw_xml, "Channel"))
        .unwrap_or_else(|| "unknown_log".to_string());
    format!(
        "{} | cleared={} | {}",
        event.time_created,
        log_file,
        truncate_text(&event.message, 220),
    )
}

fn collect_clear_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_clear_command(&normalized) {
                continue;
            }

            out.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 200),
            ));
        }
    }

    out.sort();
    out.dedup();
    out
}

fn looks_like_clear_command(text_lower: &str) -> bool {
    CLEAR_COMMAND_NEEDLES
        .iter()
        .any(|needle| text_lower.contains(needle))
}

fn collect_suspicious_log_states(states: &[EventLogState]) -> Vec<String> {
    let mut out = Vec::new();
    let now = Utc::now();

    for state in states {
        if state.error.is_some() {
            continue;
        }

        if state.is_enabled == Some(false) {
            out.push(format!(
                "{} | enabled=false mode={} records={} file_size={}",
                state.log_name,
                state
                    .log_mode
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                state
                    .record_count
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                state
                    .file_size_bytes
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        if state.record_count == Some(0) && is_recent_within(&state.last_write_time_utc, now, 72) {
            out.push(format!(
                "{} | record_count=0 oldest={} last_write={} last_access={}",
                state.log_name,
                state
                    .oldest_record_number
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                state
                    .last_write_time_utc
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                state
                    .last_access_time_utc
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        if let (Some(records), Some(size)) = (state.record_count, state.file_size_bytes) {
            if records <= 4
                && size <= 98_304
                && is_recent_within(&state.last_write_time_utc, now, 48)
            {
                out.push(format!(
                    "{} | very low records={} oldest={} file_size={} bytes mode={}",
                    state.log_name,
                    records,
                    state
                        .oldest_record_number
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    size,
                    state
                        .log_mode
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string())
                ));
            }
        }
    }

    out
}

fn is_recent_within(
    timestamp_rfc3339: &Option<String>,
    now_utc: DateTime<Utc>,
    hours: i64,
) -> bool {
    let Some(value) = timestamp_rfc3339 else {
        return false;
    };
    let Ok(parsed) = DateTime::parse_from_rfc3339(value) else {
        return false;
    };
    let parsed_utc = parsed.with_timezone(&Utc);
    parsed_utc <= now_utc && parsed_utc >= now_utc - Duration::hours(hours)
}

#[cfg(test)]
mod tests {
    use super::{collect_suspicious_log_states, looks_like_clear_command};
    use crate::bypass_scan::utils::EventLogState;

    #[test]
    fn command_match_requires_clear_patterns() {
        assert!(looks_like_clear_command(
            "powershell clear-eventlog -logname security"
        ));
        assert!(looks_like_clear_command("wevtutil cl security"));
        assert!(!looks_like_clear_command("wevtutil gl security"));
    }

    #[test]
    fn metadata_errors_are_not_suspicious_by_default() {
        let state = EventLogState {
            log_name: "Security".to_string(),
            record_count: None,
            oldest_record_number: None,
            file_size_bytes: None,
            is_enabled: None,
            log_mode: None,
            log_file_path: None,
            last_write_time_utc: None,
            last_access_time_utc: None,
            error: Some("Access denied".to_string()),
        };
        assert!(collect_suspicious_log_states(&[state]).is_empty());
    }
}
