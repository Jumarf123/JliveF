pub mod csrss;
pub mod executed_files;
pub mod import_code;
pub mod java_scan;
pub mod macro_files;
pub mod macro_strings;
pub mod memory_tool;
pub mod mods;

use std::thread;

use anyhow::Result;

use crate::core::report::{ModuleDescriptor, ModuleReport};

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        id: 3,
        label: "Memory, Macros, and Processes",
        summary: "",
    }
}

pub fn run() -> Result<ModuleReport> {
    let mut report = ModuleReport::new(descriptor());
    let descriptor = descriptor();

    memory_tool::report_availability(&mut report);

    let executed_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        executed_files::run(&mut partial)?;
        Ok(partial)
    });
    let import_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        import_code::run(&mut partial)?;
        Ok(partial)
    });
    let macro_strings_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        macro_strings::run(&mut partial)?;
        Ok(partial)
    });
    let java_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        java_scan::run(&mut partial)?;
        Ok(partial)
    });
    let macro_files_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        macro_files::run(&mut partial)?;
        Ok(partial)
    });
    let mods_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        mods::run(&mut partial)?;
        Ok(partial)
    });

    csrss::run(&mut report)?;

    report.merge(
        executed_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Executed-files worker panicked"))??,
    );
    report.merge(
        import_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Import-code worker panicked"))??,
    );
    report.merge(
        macro_strings_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Macro-string worker panicked"))??,
    );
    report.merge(
        java_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Java memory worker panicked"))??,
    );
    report.merge(
        macro_files_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Macro-file worker panicked"))??,
    );
    report.merge(
        mods_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Mods worker panicked"))??,
    );

    Ok(report.finish())
}
