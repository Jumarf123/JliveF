use anyhow::Result;
use serde::Deserialize;

use crate::core::paths::boot_time_local;
use crate::core::report::ModuleReport;
use crate::core::shell::{run_powershell, run_powershell_json_array};
use crate::core::time::{format_datetime, parse_powershell_datetime};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct EventEntry {
    TimeCreated: Option<String>,
    Id: Option<u32>,
    ProviderName: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    validate_eventlog_registry(report)?;
    scan_system_time_change(report)?;
    Ok(())
}

fn validate_eventlog_registry(report: &mut ModuleReport) -> Result<()> {
    let value = run_powershell(
        "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System' -Name File -ErrorAction SilentlyContinue).File",
    )?;
    let normalized = value.trim();
    let expected = "%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx";
    let expanded_expected = run_powershell(
        "[Environment]::ExpandEnvironmentVariables('%SystemRoot%\\System32\\Winevt\\Logs\\System.evtx')",
    )?;
    let expanded_expected = expanded_expected.trim();

    if normalized.eq_ignore_ascii_case(expected)
        || normalized.eq_ignore_ascii_case(expanded_expected)
    {
        report.add_info(
            "Eventlog path is unchanged",
            format!("Registry File={normalized}"),
        );
    } else {
        report.add_warning(
            "Eventlog path differs from the expected value",
            format!("Expected `{expected}`, found `{normalized}`."),
        );
    }

    Ok(())
}

fn scan_system_time_change(report: &mut ModuleReport) -> Result<()> {
    let events: Vec<EventEntry> = run_powershell_json_array(
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=22; ProviderName='Microsoft-Windows-Kernel-General'} -MaxEvents 1 -ErrorAction SilentlyContinue | \
         Select-Object TimeCreated, Id, ProviderName",
    )?;
    let boot_time = boot_time_local();

    if let Some(event) = events.first()
        && let Some(created) = event
            .TimeCreated
            .as_deref()
            .and_then(parse_powershell_datetime)
    {
        if created > boot_time {
            report.add_warning(
                "System time changed after boot",
                format!(
                    "EventId={}, Provider={}, TimeCreated={}",
                    event.Id.unwrap_or_default(),
                    event.ProviderName.clone().unwrap_or_default(),
                    format_datetime(&created)
                ),
            );
        } else {
            report.add_info(
                "No post-boot system time change found",
                format!(
                    "Last Kernel-General 22 event: {}",
                    format_datetime(&created)
                ),
            );
        }
    }

    Ok(())
}
