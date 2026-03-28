use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, REG_DWORD};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{EventRecord, query_event_records, truncate_text};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        11,
        "bypass11_hidden_cmd_text",
        "Hidden CMD text via color collision",
        "No console profiles with equal foreground/background color found.",
    );

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(base) = hkcu.open_subkey_with_flags("Console", KEY_READ) else {
        result.status = DetectionStatus::Error;
        result.summary = "Failed to open HKCU\\Console".to_string();
        result.error = Some("registry open failed".to_string());
        return result;
    };

    let mut suspicious = Vec::new();
    walk_console_color_keys(&base, "HKCU\\Console", &mut suspicious, 0);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_hidden_text_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    if !suspicious.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = if !command_hits.is_empty() {
            Confidence::High
        } else {
            Confidence::Medium
        };
        result.summary =
            "Detected ScreenColors values where text color equals background color.".to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Console color-collision change commands detected without current registry collision."
                .to_string();
    }

    if !suspicious.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "HKCU\\Console".to_string(),
            summary: format!("{} suspicious color profile(s)", suspicious.len()),
            details: suspicious.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} hidden-text command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Reset CMD/PowerShell color profiles or delete custom console subkeys.".to_string(),
        );
    }

    logger.log(
        "bypass11_hidden_cmd_text",
        "info",
        "console color inspection complete",
        serde_json::json!({
            "suspicious": suspicious.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn walk_console_color_keys(key: &RegKey, path: &str, suspicious: &mut Vec<String>, depth: usize) {
    if depth > 6 {
        return;
    }

    if let Some(screen_colors) = read_dword(key, "ScreenColors") {
        let fg = screen_colors & 0x0F;
        let bg = (screen_colors >> 4) & 0x0F;
        if fg == bg {
            suspicious.push(format!(
                "{}\\ScreenColors=0x{:X} (fg=bg={})",
                path, screen_colors, fg
            ));
        }
    }

    for sub in key.enum_keys().flatten() {
        if let Ok(subkey) = key.open_subkey_with_flags(&sub, KEY_READ) {
            let next = format!("{}\\{}", path, sub);
            walk_console_color_keys(&subkey, &next, suspicious, depth + 1);
        }
    }
}

fn read_dword(key: &RegKey, name: &str) -> Option<u32> {
    let raw = key.get_raw_value(name).ok()?;
    if raw.vtype != REG_DWORD || raw.bytes.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([
        raw.bytes[0],
        raw.bytes[1],
        raw.bytes[2],
        raw.bytes[3],
    ]))
}

fn collect_hidden_text_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_hidden_text_command(&normalized) {
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

fn looks_like_hidden_text_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let reg_screencolors = (normalized.contains("reg add")
        || normalized.contains("set-itemproperty")
        || normalized.contains("new-itemproperty"))
        && (normalized.contains("hkcu\\console") || normalized.contains("hkcu:\\console"))
        && normalized.contains("screencolors");
    let color_collision_cli = normalized.contains("cmd")
        && normalized.contains(" color ")
        && (normalized.contains(" 00")
            || normalized.contains(" 11")
            || normalized.contains(" 22")
            || normalized.contains(" 33")
            || normalized.contains(" 44")
            || normalized.contains(" 55")
            || normalized.contains(" 66")
            || normalized.contains(" 77")
            || normalized.contains(" 88")
            || normalized.contains(" 99")
            || normalized.contains(" aa")
            || normalized.contains(" bb")
            || normalized.contains(" cc")
            || normalized.contains(" dd")
            || normalized.contains(" ee")
            || normalized.contains(" ff"));
    reg_screencolors || color_collision_cli
}

#[cfg(test)]
mod tests {
    use super::looks_like_hidden_text_command;

    #[test]
    fn hidden_text_command_matcher_detects_registry_and_color_shapes() {
        assert!(looks_like_hidden_text_command(
            "reg add HKCU\\Console /v ScreenColors /t REG_DWORD /d 0 /f",
        ));
        assert!(looks_like_hidden_text_command("cmd.exe /c color 00"));
        assert!(!looks_like_hidden_text_command("reg query HKCU\\Console"));
    }
}
