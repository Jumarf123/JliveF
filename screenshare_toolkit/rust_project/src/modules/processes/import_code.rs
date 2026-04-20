use anyhow::Result;

use crate::core::report::ModuleReport;

use super::memory_tool;

const PATTERNS: [(&str, &str); 3] = [
    ("Invoke-RestMethod", "PowerShell download cradle"),
    ("Invoke-Expression", "PowerShell code execution"),
    ("import base64", "Python base64 import"),
];

pub fn run(report: &mut ModuleReport) -> Result<()> {
    for service_name in ["diagtrack", "eventlog"] {
        let Some(pid) = memory_tool::get_service_pid(service_name)? else {
            if service_name.eq_ignore_ascii_case("eventlog") {
                report.add_critical(
                    "Eventlog service not found",
                    "The Eventlog service is required for import-code and log checks.",
                );
            }
            continue;
        };

        let output = memory_tool::scan_pid(pid)?;
        for (pattern, label) in PATTERNS {
            if output.contains(pattern) {
                report.add_warning(
                    format!("ImportCode string in {service_name}"),
                    format!("{label}: found `{pattern}` in PID {pid}."),
                );
            }
        }
    }

    Ok(())
}
