use anyhow::Result;
use serde::Deserialize;

use crate::core::paths::boot_time_local;
use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;
use crate::core::time::{format_datetime, parse_powershell_datetime};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct PrefetchEntry {
    Name: Option<String>,
    LastWriteTime: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let boot_time = boot_time_local();
    let entries: Vec<PrefetchEntry> = run_powershell_json_array(
        "Get-ChildItem 'C:\\Windows\\Prefetch\\*.pf' -ErrorAction SilentlyContinue | \
         Where-Object { $_.Name -like 'SYSTEMINFORMER.EXE-*' -or $_.Name -like 'PROCESSHACKER.EXE-*' } | \
         Select-Object Name, @{ Name='LastWriteTime'; Expression = { $_.LastWriteTime.ToString('o') } }",
    )?;

    for entry in entries {
        if let Some(last_write) = entry
            .LastWriteTime
            .as_deref()
            .and_then(parse_powershell_datetime)
            && last_write > boot_time
        {
            report.add_warning(
                "System Informer / Process Hacker detected in Prefetch",
                format!(
                    "{} at {}",
                    entry.Name.clone().unwrap_or_default(),
                    format_datetime(&last_write)
                ),
            );
        }
    }

    Ok(())
}
