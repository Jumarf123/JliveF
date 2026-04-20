use anyhow::Result;

use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let is_admin = run_powershell(
        "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); \
         $principal = [Security.Principal.WindowsPrincipal]::new($identity); \
         $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    )?;

    if is_admin.trim().eq_ignore_ascii_case("True") {
        report.add_info(
            "Administrator rights confirmed",
            "This process can access elevated WMI, services, and journal queries.",
        );
    } else {
        report.add_critical(
            "Administrator rights missing",
            "Some Windows checks will be incomplete until the executable is started as administrator.",
        );
    }

    Ok(())
}
