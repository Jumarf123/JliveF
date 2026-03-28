use serde_json::Value;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, run_powershell, truncate_text};

const TARGET_SERVICES: &[&str] = &["SysMain", "DPS", "PcaSvc", "EventLog", "DusmSvc"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        5,
        "bypass05_service_threads",
        "Service thread suspension abuse",
        "No clear service health anomalies for targeted services.",
    );

    let services = read_services();
    let system_events = query_event_records("System", &[7031, 7034, 7040], 180);

    let service_issues = collect_service_state_issues(&services);
    let service_event_hits = collect_target_service_event_hits(&system_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_service_tamper_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    if !service_issues.is_empty() && (!service_event_hits.is_empty() || !command_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Critical service state anomalies correlate with crash/start-type events or tamper commands."
                .to_string();
    } else if !service_event_hits.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Service control/tamper commands correlate with targeted service instability events."
                .to_string();
    } else if !service_issues.is_empty()
        || !service_event_hits.is_empty()
        || !command_hits.is_empty()
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Single service tamper indicator detected (state/event/command).".to_string();
    }

    if !service_issues.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Get-Service".to_string(),
            summary: format!(
                "{} non-running auto-start target service(s)",
                service_issues.len()
            ),
            details: service_issues.join("; "),
        });
    }

    if !service_event_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "System Event Log (7031/7034/7040)".to_string(),
            summary: format!("{} target-service event(s)", service_event_hits.len()),
            details: service_event_hits.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} service tamper command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate with process/thread telemetry (Sysmon/EDR) and service baseline before final attribution."
                .to_string(),
        );
    }

    logger.log(
        "bypass05_service_threads",
        "info",
        "service anomaly scan complete",
        serde_json::json!({
            "services_checked": services.len(),
            "service_issues": service_issues.len(),
            "service_events": service_event_hits.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn read_services() -> Vec<Value> {
    let script = "Get-Service | Where-Object { $_.Name -in @('SysMain','DPS','PcaSvc','EventLog','DusmSvc') -or $_.Name -like 'CDPUserSvc*' } | Select-Object Name,Status,StartType | ConvertTo-Json -Compress";
    let Some(raw) = run_powershell(script) else {
        return Vec::new();
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Array(items)) => items,
        Ok(item) => vec![item],
        Err(_) => Vec::new(),
    }
}

fn collect_service_state_issues(services: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for svc in services {
        if let (Some(name), Some(status), Some(start_type)) = (
            svc.get("Name").and_then(Value::as_str),
            svc.get("Status").and_then(Value::as_str),
            svc.get("StartType").and_then(Value::as_str),
        ) {
            if (TARGET_SERVICES.iter().any(|x| x.eq_ignore_ascii_case(name))
                || name.to_lowercase().starts_with("cdpusersvc"))
                && start_type.to_lowercase().contains("automatic")
                && !status.eq_ignore_ascii_case("Running")
            {
                out.push(format!("{name}: status={status}, start={start_type}"));
            }
        }
    }
    out
}

fn collect_target_service_event_hits(events: &[EventRecord]) -> Vec<String> {
    let mut out = Vec::new();
    for event in events {
        let msg_l = event.message.to_lowercase();
        if TARGET_SERVICES
            .iter()
            .any(|svc| msg_l.contains(&svc.to_lowercase()))
            || msg_l.contains("cdpusersvc")
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

fn collect_service_tamper_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_service_tamper_command(&text) {
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

fn looks_like_service_tamper_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let target = TARGET_SERVICES
        .iter()
        .any(|svc| normalized.contains(&svc.to_lowercase()))
        || normalized.contains("cdpusersvc");

    let service_stop_or_disable = (normalized.contains("sc ")
        && (normalized.contains(" stop ") || normalized.contains(" config ")))
        || normalized.contains("net stop")
        || normalized.contains("stop-service")
        || normalized.contains("set-service");
    let thread_suspend_hint = normalized.contains("pssuspend")
        || normalized.contains("suspend-process")
        || normalized.contains("processhacker")
        || normalized.contains("ntsuspendprocess");

    target && (service_stop_or_disable || thread_suspend_hint)
}

#[cfg(test)]
mod tests {
    use super::looks_like_service_tamper_command;

    #[test]
    fn service_tamper_matcher_requires_target_and_tamper_shape() {
        assert!(looks_like_service_tamper_command("sc stop EventLog"));
        assert!(looks_like_service_tamper_command(
            "Set-Service -Name SysMain -StartupType Disabled"
        ));
        assert!(!looks_like_service_tamper_command("Get-Service EventLog"));
    }
}
