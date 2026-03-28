use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, query_event_records, run_command, run_powershell, truncate_text,
};

const WEF_TAMPER_NEEDLES: &[&str] = &[
    "sc config wecsvc start= disabled",
    "set-service wecsvc -startuptype disabled",
    "stop-service wecsvc",
    "wecutil ds ",
    "wecutil ss ",
    "/e:false",
    "subscriptionmanager",
    "eventforwarding",
    "reg delete",
    "remove-item",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        28,
        "bypass28_wef_tamper",
        "Event forwarding tamper (WEF/WEC)",
        "No high-confidence event-forwarding tamper evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        240,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let command_hits = collect_wef_tamper_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let mut reg_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[12, 13, 14], 180);
    reg_events.extend(query_event_records("Security", &[4657], 180));
    let registry_hits = collect_wef_registry_hits(&reg_events);

    let wef_state = query_wef_state();
    let forwarding_expected =
        wef_state.has_subscription_manager || wef_state.subscription_count.unwrap_or(0) > 0;
    let service_anomaly =
        forwarding_expected && (wef_state.service_disabled || wef_state.service_stopped);

    if !command_hits.is_empty() && (forwarding_expected || !registry_hits.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit WEF tamper commands with forwarding configuration context."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Detected potential WEF tamper commands, but host forwarding role is unclear."
                .to_string();
    } else if service_anomaly && !registry_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "WEF service state and registry activity indicate possible forwarding tamper."
                .to_string();
    } else if service_anomaly {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "WEF service state is unusual for a forwarding-configured host, without direct tamper command traces."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} WEF tamper command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry telemetry (Sysmon/Security)".to_string(),
            summary: format!("{} WEF-related registry event(s)", registry_hits.len()),
            details: registry_hits.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "WEF runtime/config state".to_string(),
        summary: format!(
            "service_disabled={} service_stopped={} has_subscription_manager={} subscription_count={}",
            wef_state.service_disabled,
            wef_state.service_stopped,
            wef_state.has_subscription_manager,
            wef_state
                .subscription_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: format!(
            "SubscriptionManager='{}' | sc qc='{}' | sc query='{}'",
            truncate_text(&wef_state.subscription_manager, 180),
            truncate_text(&wef_state.sc_qc, 180),
            truncate_text(&wef_state.sc_query, 180),
        ),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Validate host WEF role (collector/source/none) before final attribution, then correlate with central SIEM continuity."
                .to_string(),
        );
    }

    logger.log(
        "bypass28_wef_tamper",
        "info",
        "wef tamper checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "registry_hits": registry_hits.len(),
            "service_disabled": wef_state.service_disabled,
            "service_stopped": wef_state.service_stopped,
            "has_subscription_manager": wef_state.has_subscription_manager,
            "subscription_count": wef_state.subscription_count,
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone)]
struct WefState {
    sc_qc: String,
    sc_query: String,
    service_disabled: bool,
    service_stopped: bool,
    subscription_manager: String,
    has_subscription_manager: bool,
    subscription_count: Option<usize>,
}

fn query_wef_state() -> WefState {
    let sc_qc = run_command("sc", &["qc", "wecsvc"]).unwrap_or_default();
    let sc_query = run_command("sc", &["query", "wecsvc"]).unwrap_or_default();
    let service_disabled = sc_qc.to_lowercase().contains("disabled");
    let service_stopped = sc_query.to_lowercase().contains("stopped");

    let subscription_manager = run_powershell(
        "$v = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding' -Name 'SubscriptionManager' -ErrorAction SilentlyContinue; if ($null -ne $v) { $v.SubscriptionManager -join ';' }",
    )
    .unwrap_or_default()
    .trim()
    .to_string();
    let has_subscription_manager = !subscription_manager.is_empty();

    let subscription_count = run_command("wecutil", &["es"]).and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Some(0usize);
        }
        let lowered = trimmed.to_lowercase();
        if lowered.contains("access is denied")
            || lowered.contains("not recognized")
            || lowered.contains("error")
        {
            return None;
        }
        Some(
            trimmed
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count(),
        )
    });

    WefState {
        sc_qc,
        sc_query,
        service_disabled,
        service_stopped,
        subscription_manager,
        has_subscription_manager,
        subscription_count,
    }
}

fn collect_wef_tamper_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_wef_tamper_command(&normalized) {
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

fn collect_wef_registry_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if normalized.contains("eventforwarding")
            || normalized.contains("subscriptionmanager")
            || normalized.contains("wecsvc")
        {
            hits.push(format!(
                "{} | Event {} | {}",
                event.time_created,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }
    hits
}

fn looks_like_wef_tamper_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let has_any = WEF_TAMPER_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle));
    if !has_any {
        return false;
    }

    (normalized.contains("wecsvc")
        && (normalized.contains("disabled")
            || normalized.contains("stop-service")
            || normalized.contains("sc config")))
        || (normalized.contains("wecutil")
            && (normalized.contains(" ds ")
                || (normalized.contains(" ss ") && normalized.contains("/e:false"))))
        || ((normalized.contains("eventforwarding") || normalized.contains("subscriptionmanager"))
            && (normalized.contains("reg delete")
                || normalized.contains("remove-item")
                || normalized.contains("remove-itemproperty")))
}

#[cfg(test)]
mod tests {
    use super::looks_like_wef_tamper_command;

    #[test]
    fn wef_tamper_matcher_detects_destructive_shapes() {
        assert!(looks_like_wef_tamper_command(
            "sc config wecsvc start= disabled"
        ));
        assert!(looks_like_wef_tamper_command("wecutil ss sub1 /e:false"));
        assert!(!looks_like_wef_tamper_command("wecutil es"));
    }
}
