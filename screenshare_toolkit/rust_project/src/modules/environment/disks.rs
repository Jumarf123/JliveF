use anyhow::Result;
use serde::Deserialize;

use crate::core::paths::boot_time_local;
use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;
use crate::core::time::{format_datetime, parse_powershell_datetime};

#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct DiskEntry {
    DeviceID: Option<String>,
    FileSystem: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct ItemInfo {
    FullName: Option<String>,
    LastWriteTime: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let boot_time = boot_time_local();
    let disks: Vec<DiskEntry> = run_powershell_json_array(
        "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, FileSystem",
    )?;

    for disk in disks {
        let Some(device_id) = disk.DeviceID else {
            continue;
        };

        if device_id.eq_ignore_ascii_case("C:") {
            continue;
        }

        let path = format!("{device_id}\\System Volume Information");
        let entries: Vec<ItemInfo> = run_powershell_json_array(&format!(
            "Get-Item -LiteralPath '{}' -Force -ErrorAction SilentlyContinue | Select-Object FullName, LastWriteTime",
            path.replace('\'', "''")
        ))?;

        if let Some(entry) = entries.first()
            && let Some(timestamp) = entry
                .LastWriteTime
                .as_deref()
                .and_then(parse_powershell_datetime)
            && timestamp > boot_time
        {
            report.add_warning(
                format!("Suspicious disk activity on {device_id}"),
                format!(
                    "{} was modified after boot at {}",
                    entry.FullName.clone().unwrap_or(path.clone()),
                    format_datetime(&timestamp)
                ),
            );
        }
    }
    Ok(())
}
