use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, run_command, truncate_text,
};

const SHADOW_DELETE_NEEDLES: &[&str] = &[
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "remove-wmiobject win32_shadowcopy",
    "get-wmiobject win32_shadowcopy",
    "remove-ciminstance",
    "diskshadow",
    "delete shadows all",
    "wbadmin delete catalog",
];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        20,
        "bypass20_shadowcopy_delete",
        "Shadow copy / restore point deletion",
        "No high-confidence shadow-copy deletion evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        300,
    );
    let sec_events = query_event_records("Security", &[4688], 360);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 300);

    let command_hits = collect_shadow_delete_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let tool_prefetch = prefetch_file_names_by_prefixes(&[
        "VSSADMIN.EXE-",
        "WMIC.EXE-",
        "POWERSHELL.EXE-",
        "DISKSHADOW.EXE-",
        "WBADMIN.EXE-",
    ]);

    let wmic_list = run_command("wmic", &["shadowcopy", "get", "ID", "/value"]).unwrap_or_default();
    let vssadmin_list = run_command("vssadmin", &["list", "shadows"]).unwrap_or_default();
    let shadowcopy_count = parse_shadowcopy_count_from_wmic(&wmic_list)
        .or_else(|| parse_shadowcopy_count_from_vssadmin(&vssadmin_list));
    let no_shadows = shadowcopy_count == Some(0)
        || vssadmin_indicates_no_shadows(&vssadmin_list)
        || wmic_indicates_no_shadows(&wmic_list);
    let inventory_source = if parse_shadowcopy_count_from_wmic(&wmic_list).is_some() {
        "wmic shadowcopy get ID /value"
    } else {
        "vssadmin list shadows"
    };

    if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected explicit shadow-copy deletion command traces.".to_string();
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} deletion command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    } else if !tool_prefetch.is_empty() && no_shadows {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Shadow-copy tooling traces found while no shadow copies are currently present."
                .to_string();
    } else if no_shadows {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "No shadow copies detected, but direct deletion commands were not observed."
                .to_string();
    }

    if !tool_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} related tool prefetch file(s)", tool_prefetch.len()),
            details: tool_prefetch.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Shadow-copy inventory".to_string(),
        summary: format!(
            "source={} shadow_copy_count={} no_shadows={}",
            inventory_source,
            shadowcopy_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            no_shadows
        ),
        details: if shadowcopy_count.is_some() {
            "Inventory parsed successfully.".to_string()
        } else {
            "Could not parse shadow-copy count from command output.".to_string()
        },
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate command traces with adjacent ransomware/cleanup activity and preserve remote logs."
                .to_string(),
        );
        result.recommendations.push(
            "Validate whether backup/maintenance tooling could legitimately delete shadow copies."
                .to_string(),
        );
    }

    logger.log(
        "bypass20_shadowcopy_delete",
        "info",
        "shadow copy checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "tool_prefetch": tool_prefetch.len(),
            "shadowcopy_count": shadowcopy_count,
            "no_shadows": no_shadows,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_shadow_delete_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_shadow_delete_command(&normalized) {
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

fn looks_like_shadow_delete_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    SHADOW_DELETE_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn vssadmin_indicates_no_shadows(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("no items found that satisfy the query")
        || lower.contains("элементы не найдены")
        || lower.contains("нет элементов")
}

fn wmic_indicates_no_shadows(output: &str) -> bool {
    let lower = output.to_lowercase();
    lower.contains("no instance(s) available")
        || lower.contains("нет доступных экземпляров")
        || lower.contains("нет экземпляров")
}

fn parse_shadowcopy_count_from_wmic(output: &str) -> Option<u64> {
    if output.trim().is_empty() {
        return None;
    }
    if wmic_indicates_no_shadows(output) {
        return Some(0);
    }

    let count = output
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("ID={") && trimmed.ends_with('}')
        })
        .count();

    if count > 0 { Some(count as u64) } else { None }
}

fn parse_shadowcopy_count_from_vssadmin(output: &str) -> Option<u64> {
    if output.trim().is_empty() {
        return None;
    }
    if vssadmin_indicates_no_shadows(output) {
        return Some(0);
    }

    // Each shadow entry has a unique "Shadow Copy ID" marker.
    let count = output.to_lowercase().matches("shadow copy id").count();

    if count > 0 { Some(count as u64) } else { None }
}

#[cfg(test)]
mod tests {
    use super::{
        looks_like_shadow_delete_command, parse_shadowcopy_count_from_vssadmin,
        parse_shadowcopy_count_from_wmic, vssadmin_indicates_no_shadows, wmic_indicates_no_shadows,
    };

    #[test]
    fn shadow_command_matcher_detects_delete_patterns() {
        assert!(looks_like_shadow_delete_command(
            "cmd /c vssadmin delete shadows /all /quiet"
        ));
        assert!(looks_like_shadow_delete_command(
            "wmic shadowcopy delete /nointeractive"
        ));
        assert!(!looks_like_shadow_delete_command("vssadmin list shadows"));
    }

    #[test]
    fn vss_count_parser_handles_empty_and_no_items() {
        assert_eq!(
            parse_shadowcopy_count_from_vssadmin(
                "vssadmin 1.1\nNo items found that satisfy the query."
            ),
            Some(0)
        );
        assert!(vssadmin_indicates_no_shadows(
            "Элементы не найдены, соответствующие запросу."
        ));
    }

    #[test]
    fn vss_count_parser_counts_shadow_copy_id_entries() {
        let sample = r#"
Contents of shadow copy set ID: {11111111-1111-1111-1111-111111111111}
   Shadow Copy ID: {aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}
Contents of shadow copy set ID: {22222222-2222-2222-2222-222222222222}
   Shadow Copy ID: {bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}
"#;
        assert_eq!(parse_shadowcopy_count_from_vssadmin(sample), Some(2));
    }

    #[test]
    fn wmic_count_parser_handles_no_instances_and_ids() {
        assert!(wmic_indicates_no_shadows("No Instance(s) Available."));
        assert_eq!(
            parse_shadowcopy_count_from_wmic(
                "ID={aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}\n\nID={bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}\n"
            ),
            Some(2)
        );
    }
}
