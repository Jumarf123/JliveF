use anyhow::Result;
use serde::Deserialize;

use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct PsDriveEntry {
    Name: Option<String>,
    Root: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let mappings: Vec<PsDriveEntry> = run_powershell_json_array(
        "Get-PSDrive -PSProvider FileSystem | \
         Where-Object { $_.Root -like '\\\\*' } | \
         Select-Object Name, Root",
    )?;

    if mappings.is_empty() {
        report.add_info(
            "No mapped network shares",
            "No filesystem PSDrive roots were mapped to UNC paths.",
        );
        return Ok(());
    }

    for mapping in mappings {
        report.add_warning(
            format!(
                "Network share {}",
                mapping.Name.unwrap_or_else(|| "?".to_string())
            ),
            format!(
                "Root={}. Review whether tools are being launched from a network path.",
                mapping.Root.unwrap_or_else(|| "<unknown>".to_string())
            ),
        );
    }

    Ok(())
}
