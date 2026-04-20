use anyhow::Result;

use crate::core::native;
use crate::core::report::ModuleReport;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    match native::detect_vm()? {
        Some(brand) => report.add_warning(
            "Virtual machine indicators detected",
            format!("Detected VM brand: {brand}."),
        ),
        None => report.add_info(
            "No virtual machine indicators detected",
            "The VM fingerprint check completed without a hit.",
        ),
    }

    Ok(())
}
