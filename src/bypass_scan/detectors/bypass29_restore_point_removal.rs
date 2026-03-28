use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, run_command, run_powershell,
    truncate_text,
};

const TOOL_PREFIXES: &[&str] = &[
    "VSSADMIN.EXE-",
    "WMIC.EXE-",
    "POWERSHELL.EXE-",
    "DISKSHADOW.EXE-",
    "WBADMIN.EXE-",
];

const RESTORE_REG_PATH: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
const RESTORE_POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore";

const RESTORE_DELETE_NEEDLES: &[&str] = &[
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "disable-computerrestore",
    "enable-computerrestore",
    "srremoverestorepoint",
    "remove-wmiobject win32_shadowcopy",
    "delete shadows all",
    "wbadmin delete catalog",
    "diskshadow",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        29,
        "bypass29_restore_point_removal",
        "System Restore point removal",
        "No high-confidence restore-point deletion evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 340);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 260);
    let command_hits = collect_restore_delete_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let restore_count = run_powershell(
        "$ErrorActionPreference='SilentlyContinue'; try { (Get-ComputerRestorePoint | Measure-Object).Count } catch { '' }",
    )
    .and_then(|s| s.trim().parse::<u32>().ok());

    let list_shadows = run_command("vssadmin", &["list", "shadows"]).unwrap_or_default();
    let list_lower = list_shadows.to_lowercase();
    let no_shadows = list_lower.contains("no items found")
        || list_lower.contains("not found")
        || list_lower.contains("no items found that satisfy the query");

    let tool_prefetch = prefetch_file_names_by_prefixes(TOOL_PREFIXES);
    let restore_reg_state = read_restore_registry_state();

    if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit restore-point/shadow-delete command traces.".to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} destructive command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if restore_count == Some(0)
        && (no_shadows || !tool_prefetch.is_empty())
        && (restore_reg_state.disable_sr == Some(1)
            || restore_reg_state.policy_disable_sr == Some(1))
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "System Restore appears disabled and no restore points are currently available."
                .to_string();
    } else if restore_count == Some(0) && (no_shadows || !tool_prefetch.is_empty()) {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "No restore points currently present, but no direct deletion command was captured."
                .to_string();
    } else if restore_reg_state.disable_sr == Some(1)
        || restore_reg_state.policy_disable_sr == Some(1)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "System Restore disable flags are enabled without direct deletion command traces."
                .to_string();
    }

    if !tool_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} related prefetch file(s)", tool_prefetch.len()),
            details: tool_prefetch.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Restore point inventory".to_string(),
        summary: format!(
            "restore_point_count={} no_shadows={}",
            restore_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            no_shadows
        ),
        details: truncate_text(&list_shadows.replace('\n', " "), 260),
    });

    result.evidence.push(EvidenceItem {
        source: format!("HKLM\\{} + HKLM\\{}", RESTORE_REG_PATH, RESTORE_POLICY_PATH),
        summary: format!(
            "DisableSR={} DisableConfig={} PolicyDisableSR={} PolicyDisableConfig={}",
            restore_reg_state
                .disable_sr
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            restore_reg_state
                .disable_config
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            restore_reg_state
                .policy_disable_sr
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            restore_reg_state
                .policy_disable_config
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        details: String::new(),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate restore-point deletion indicators with VSS commands and adjacent anti-forensic actions."
                .to_string(),
        );
        result.recommendations.push(
            "Validate baseline backup policy to distinguish intentional hardening from malicious cleanup."
                .to_string(),
        );
    }

    logger.log(
        "bypass29_restore_point_removal",
        "info",
        "restore point checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "restore_count": restore_count,
            "no_shadows": no_shadows,
            "prefetch_hits": tool_prefetch.len(),
            "disable_sr": restore_reg_state.disable_sr,
            "policy_disable_sr": restore_reg_state.policy_disable_sr,
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone)]
struct RestoreRegistryState {
    disable_sr: Option<u32>,
    disable_config: Option<u32>,
    policy_disable_sr: Option<u32>,
    policy_disable_config: Option<u32>,
}

fn read_restore_registry_state() -> RestoreRegistryState {
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
    let main_key = hk.open_subkey_with_flags(RESTORE_REG_PATH, KEY_READ).ok();
    let policy_key = hk
        .open_subkey_with_flags(RESTORE_POLICY_PATH, KEY_READ)
        .ok();

    RestoreRegistryState {
        disable_sr: main_key
            .as_ref()
            .and_then(|k| k.get_value::<u32, _>("DisableSR").ok()),
        disable_config: main_key
            .as_ref()
            .and_then(|k| k.get_value::<u32, _>("DisableConfig").ok()),
        policy_disable_sr: policy_key
            .as_ref()
            .and_then(|k| k.get_value::<u32, _>("DisableSR").ok()),
        policy_disable_config: policy_key
            .as_ref()
            .and_then(|k| k.get_value::<u32, _>("DisableConfig").ok()),
    }
}

fn collect_restore_delete_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_restore_delete_command(&normalized) {
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

fn looks_like_restore_delete_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    RESTORE_DELETE_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::looks_like_restore_delete_command;

    #[test]
    fn restore_delete_matcher_detects_known_commands() {
        assert!(looks_like_restore_delete_command(
            "powershell Disable-ComputerRestore -Drive C:\\"
        ));
        assert!(looks_like_restore_delete_command(
            "cmd /c vssadmin delete shadows /all /quiet"
        ));
        assert!(!looks_like_restore_delete_command("vssadmin list shadows"));
    }
}
