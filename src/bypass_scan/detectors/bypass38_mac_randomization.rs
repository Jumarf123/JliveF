use serde_json::Value;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, query_event_records, run_command, run_powershell, truncate_text,
};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        38,
        "bypass38_mac_randomization",
        "MAC randomization tamper",
        "No strong MAC-randomization tamper command evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_mac_change_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let wlan_randomization_raw =
        run_command("netsh", &["wlan", "show", "randomization"]).unwrap_or_default();
    let wlan_randomization_enabled = parse_wlan_randomization_enabled(&wlan_randomization_raw);
    let registry_mac_overrides = query_registry_mac_overrides();

    if !command_hits.is_empty()
        && (!registry_mac_overrides.is_empty() || wlan_randomization_enabled)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit MAC randomization/change commands with matching current adapter state."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Detected explicit MAC randomization/network-address manipulation commands."
                .to_string();
    } else if !registry_mac_overrides.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Adapter registry shows explicit NetworkAddress override values (possible MAC spoofing)."
                .to_string();
    } else if wlan_randomization_enabled {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "WLAN randomization appears enabled; often benign, but still relevant for anti-correlation analysis."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} MAC-randomization command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !registry_mac_overrides.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Registry adapter overrides".to_string(),
            summary: format!(
                "{} adapter NetworkAddress override(s)",
                registry_mac_overrides.len()
            ),
            details: registry_mac_overrides.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "netsh wlan show randomization".to_string(),
        summary: format!("randomization_enabled={wlan_randomization_enabled}"),
        details: truncate_text(&wlan_randomization_raw.replace('\n', " | "), 280),
    });

    logger.log(
        "bypass38_mac_randomization",
        "info",
        "mac randomization checks complete",
        serde_json::json!({
            "cmd_hits": command_hits.len(),
            "registry_mac_overrides": registry_mac_overrides.len(),
            "wlan_randomization_enabled": wlan_randomization_enabled,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_mac_change_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_mac_change_command(&text) {
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

fn looks_like_mac_change_command(text: &str) -> bool {
    let normalized = text.to_lowercase();

    let wlan_toggle = normalized.contains("netsh wlan set randomization")
        && (normalized.contains("enabled=yes")
            || normalized.contains("enabled = yes")
            || normalized.contains("enabled=no")
            || normalized.contains("enabled = no"));

    let adapter_override = normalized.contains("set-netadapteradvancedproperty")
        && (normalized.contains("networkaddress")
            || normalized.contains("network address")
            || normalized.contains("locally administered address")
            || normalized.contains("mac"));

    let reg_override = normalized.contains("networkaddress")
        && normalized.contains("reg add")
        && normalized.contains("control\\class\\{4d36e972-e325-11ce-bfc1-08002be10318}");

    wlan_toggle || adapter_override || reg_override
}

fn parse_wlan_randomization_enabled(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("enabled")
        || lower.contains("включено")
        || lower.contains("yes")
        || lower.contains("да")
}

fn query_registry_mac_overrides() -> Vec<String> {
    let script = r#"
$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
if (-not (Test-Path $base)) { return }
Get-ChildItem -Path $base -ErrorAction SilentlyContinue |
  ForEach-Object {
    $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
    if ($null -ne $p -and $p.NetworkAddress) {
      [PSCustomObject]@{
        Key = $_.PSChildName
        DriverDesc = $p.DriverDesc
        NetworkAddress = $p.NetworkAddress
      }
    }
  } | ConvertTo-Json -Compress
"#;
    let Some(raw) = run_powershell(script) else {
        return Vec::new();
    };
    let text = raw.trim();
    if text.is_empty() {
        return Vec::new();
    }

    let parse = |item: &Value| -> Option<String> {
        let key = item.get("Key").and_then(Value::as_str).unwrap_or("unknown");
        let desc = item
            .get("DriverDesc")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let mac = item
            .get("NetworkAddress")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        Some(format!("{key} {desc} NetworkAddress={mac}"))
    };

    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => items.iter().filter_map(parse).collect(),
        Ok(item) => parse(&item).into_iter().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{looks_like_mac_change_command, parse_wlan_randomization_enabled};

    #[test]
    fn mac_change_command_matcher_detects_common_paths() {
        assert!(looks_like_mac_change_command(
            "netsh wlan set randomization enabled=yes interface=\"Wi-Fi\""
        ));
        assert!(looks_like_mac_change_command(
            "Set-NetAdapterAdvancedProperty -Name Wi-Fi -DisplayName \"Network Address\" -DisplayValue 001122334455"
        ));
        assert!(!looks_like_mac_change_command("netsh wlan show interfaces"));
    }

    #[test]
    fn wlan_randomization_parser_handles_english_and_ru() {
        assert!(parse_wlan_randomization_enabled("Randomization: Enabled"));
        assert!(parse_wlan_randomization_enabled("Случайный MAC: Включено"));
        assert!(!parse_wlan_randomization_enabled("Disabled"));
    }
}
