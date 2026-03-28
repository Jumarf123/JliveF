use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, query_event_records, run_command, run_powershell, truncate_text,
};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        40,
        "bypass40_secure_boot_tamper",
        "Secure Boot / BCD tamper",
        "No high-confidence BCD tamper command evidence found.",
    );

    let bcd_output = run_command("bcdedit", &["/enum"]).unwrap_or_default();
    let insecure_flags = extract_insecure_bcd_flags(&bcd_output);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let cmd_hits = collect_bcd_tamper_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let secure_boot_state_raw =
        run_powershell("try { Confirm-SecureBootUEFI } catch { 'unknown' }")
            .unwrap_or_else(|| "unknown".to_string())
            .trim()
            .to_string();
    let secure_boot_state = parse_secure_boot_state(&secure_boot_state_raw);

    if !cmd_hits.is_empty() && !insecure_flags.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "BCD tamper commands detected with matching insecure boot configuration flags."
                .to_string();
    } else if !cmd_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit BCD integrity/secure-boot weakening command traces.".to_string();
    } else if !insecure_flags.is_empty() && secure_boot_state == SecureBootState::Disabled {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Current BCD/UEFI state indicates weakened boot integrity and disabled Secure Boot."
                .to_string();
    } else if !insecure_flags.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Current BCD configuration includes insecure boot/integrity settings.".to_string();
    } else if secure_boot_state == SecureBootState::Disabled {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Secure Boot currently disabled. This can be legitimate but is relevant anti-forensic context."
                .to_string();
    }

    if !cmd_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} BCD tamper command hit(s)", cmd_hits.len()),
            details: cmd_hits.join("; "),
        });
    }

    if !insecure_flags.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "bcdedit /enum".to_string(),
            summary: format!("{} insecure BCD flag(s)", insecure_flags.len()),
            details: insecure_flags.join(", "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Confirm-SecureBootUEFI".to_string(),
        summary: "Current secure boot query state".to_string(),
        details: secure_boot_state_raw,
    });

    logger.log(
        "bypass40_secure_boot_tamper",
        "info",
        "secure boot checks complete",
        serde_json::json!({
            "cmd_hits": cmd_hits.len(),
            "insecure_flags": insecure_flags.len(),
            "secure_boot_state": format!("{:?}", secure_boot_state),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_bcd_tamper_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_bcd_tamper_command(&text) {
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

fn looks_like_bcd_tamper_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    if !(normalized.contains("bcdedit") && normalized.contains("/set")) {
        return false;
    }

    normalized.contains("testsigning on")
        || normalized.contains("nointegritychecks on")
        || normalized.contains("disable_integrity_checks")
        || normalized.contains("bootstatuspolicy ignoreallfailures")
        || normalized.contains("recoveryenabled no")
        || normalized.contains("bootmenupolicy legacy")
}

fn extract_insecure_bcd_flags(bcd_output: &str) -> Vec<String> {
    let bcd = bcd_output.to_lowercase();
    let mut flags = Vec::new();

    if bcd.contains("testsigning")
        && (bcd.contains("testsigning yes") || bcd.contains("testsigning on"))
    {
        flags.push("testsigning=on".to_string());
    }
    if bcd.contains("nointegritychecks")
        && (bcd.contains("nointegritychecks yes") || bcd.contains("nointegritychecks on"))
    {
        flags.push("nointegritychecks=on".to_string());
    }
    if bcd.contains("loadoptions")
        && (bcd.contains("ddisable_integrity_checks") || bcd.contains("disable_integrity_checks"))
    {
        flags.push("loadoptions=disable_integrity_checks".to_string());
    }
    if bcd.contains("bootstatuspolicy") && bcd.contains("ignoreallfailures") {
        flags.push("bootstatuspolicy=ignoreallfailures".to_string());
    }
    if bcd.contains("recoveryenabled") && bcd.contains("no") {
        flags.push("recoveryenabled=no".to_string());
    }
    if bcd.contains("bootmenupolicy") && bcd.contains("legacy") {
        flags.push("bootmenupolicy=legacy".to_string());
    }

    flags
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureBootState {
    Enabled,
    Disabled,
    Unknown,
}

fn parse_secure_boot_state(raw: &str) -> SecureBootState {
    let lower = raw.to_lowercase();
    if lower.contains("true") {
        return SecureBootState::Enabled;
    }
    if lower.contains("false") {
        return SecureBootState::Disabled;
    }
    SecureBootState::Unknown
}

#[cfg(test)]
mod tests {
    use super::{
        SecureBootState, extract_insecure_bcd_flags, looks_like_bcd_tamper_command,
        parse_secure_boot_state,
    };

    #[test]
    fn bcd_command_matcher_detects_integrity_weakening() {
        assert!(looks_like_bcd_tamper_command("bcdedit /set testsigning on"));
        assert!(looks_like_bcd_tamper_command(
            "bcdedit /set {default} recoveryenabled no"
        ));
        assert!(!looks_like_bcd_tamper_command("bcdedit /enum"));
    }

    #[test]
    fn insecure_flag_extraction_parses_multiple_values() {
        let sample = "testsigning Yes\nbootstatuspolicy IgnoreAllFailures\nrecoveryenabled No";
        let flags = extract_insecure_bcd_flags(sample);
        assert!(flags.contains(&"testsigning=on".to_string()));
        assert!(flags.contains(&"bootstatuspolicy=ignoreallfailures".to_string()));
        assert!(flags.contains(&"recoveryenabled=no".to_string()));
    }

    #[test]
    fn secure_boot_state_parser_handles_bool_strings() {
        assert_eq!(parse_secure_boot_state("True"), SecureBootState::Enabled);
        assert_eq!(parse_secure_boot_state("False"), SecureBootState::Disabled);
        assert_eq!(parse_secure_boot_state("unknown"), SecureBootState::Unknown);
    }
}
