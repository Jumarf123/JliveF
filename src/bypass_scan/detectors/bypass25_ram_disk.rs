use serde_json::Value;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, run_powershell, truncate_text};

const RAMDISK_TOOL_KEYWORDS: &[&str] = &[
    "imdisk",
    "osfmount",
    "softperfect ram disk",
    "amd radeon ramdisk",
    "dataram",
    "primo ramdisk",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        25,
        "bypass25_ram_disk",
        "RAM disk volatile storage",
        "No high-confidence RAM disk bypass pattern found.",
    );

    let ram_disks = query_ram_disks();
    let ramdisk_services = query_ramdisk_services();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 300);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_ramdisk_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    if !ram_disks.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Active RAM disk volume(s) correlate with explicit RAM-disk tooling commands."
                .to_string();
    } else if !ram_disks.is_empty() && !ramdisk_services.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Active RAM disk volume(s) detected with RAM-disk service/tool presence.".to_string();
    } else if !ram_disks.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "RAM disk volume(s) detected without direct command telemetry. Validate business use."
                .to_string();
    } else if !ramdisk_services.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "RAM disk software service is present, but no active RAM volume is currently detected."
                .to_string();
    }

    if !ram_disks.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Win32_LogicalDisk".to_string(),
            summary: format!("{} RAM disk volume(s) (DriveType=6)", ram_disks.len()),
            details: ram_disks.join("; "),
        });
    }

    if !ramdisk_services.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Get-Service/Get-Process".to_string(),
            summary: format!(
                "{} RAM-disk tool/service indicator(s)",
                ramdisk_services.len()
            ),
            details: ramdisk_services.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} RAM-disk command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Capture volatile RAM-disk content immediately if incident context requires evidence preservation."
                .to_string(),
        );
    }

    logger.log(
        "bypass25_ram_disk",
        "info",
        "ram disk checks complete",
        serde_json::json!({
            "ram_disks": ram_disks.len(),
            "service_hits": ramdisk_services.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn query_ram_disks() -> Vec<String> {
    let script = "Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 6 } | Select-Object DeviceID,VolumeName,FileSystem,Size | ConvertTo-Json -Compress";
    parse_entries(script, |item| {
        let dev = item.get("DeviceID")?.as_str()?;
        let volume = item
            .get("VolumeName")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let fs = item
            .get("FileSystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let size = item
            .get("Size")
            .and_then(Value::as_u64)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Some(format!("{dev} volume={volume} fs={fs} size={size}"))
    })
}

fn query_ramdisk_services() -> Vec<String> {
    let keywords = RAMDISK_TOOL_KEYWORDS.join("|");
    let service_script = format!(
        "$k='{keywords}'; Get-Service -ErrorAction SilentlyContinue | Where-Object {{ ($_.Name -match $k -or $_.DisplayName -match $k) -and $_.Status -eq 'Running' }} | Select-Object Name,Status,StartType | ConvertTo-Json -Compress"
    );
    let process_script = format!(
        "$k='{keywords}'; Get-Process -ErrorAction SilentlyContinue | Where-Object {{ $_.ProcessName -match $k }} | Select-Object ProcessName,Id | ConvertTo-Json -Compress"
    );

    let mut out = parse_entries(&service_script, |item| {
        let name = item.get("Name")?.as_str()?;
        let status = item
            .get("Status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Some(format!("service:{name} status={status}"))
    });
    out.extend(parse_entries(&process_script, |item| {
        let name = item.get("ProcessName")?.as_str()?;
        let id = item.get("Id").and_then(Value::as_i64).unwrap_or_default();
        Some(format!("process:{name} pid={id}"))
    }));

    out.sort();
    out.dedup();
    out
}

fn collect_ramdisk_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_ramdisk_command(&normalized) {
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

fn looks_like_ramdisk_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let keyword_hit = RAMDISK_TOOL_KEYWORDS
        .iter()
        .any(|needle| normalized.contains(needle));
    let shape_hit = normalized.contains("ramdisk")
        || normalized.contains("-a -s")
        || normalized.contains("mount")
        || normalized.contains("create");
    keyword_hit && shape_hit
}

fn parse_entries<F>(script: &str, map: F) -> Vec<String>
where
    F: Fn(&Value) -> Option<String>,
{
    let Some(raw) = run_powershell(script) else {
        return Vec::new();
    };
    let text = raw.trim();
    if text.is_empty() {
        return Vec::new();
    }

    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => items.iter().filter_map(&map).collect(),
        Ok(item) => map(&item).into_iter().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::looks_like_ramdisk_command;

    #[test]
    fn ramdisk_command_matcher_requires_tool_and_shape() {
        assert!(looks_like_ramdisk_command(
            "imdisk -a -s 512M -m R: -p \"/fs:ntfs /q /y\""
        ));
        assert!(!looks_like_ramdisk_command("Get-Service imdisk"));
    }
}
