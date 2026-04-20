pub mod environment;
pub mod forensics;
pub mod processes;

use anyhow::{Result, bail};

use crate::core::report::{ModuleDescriptor, ModuleReport};

pub fn catalog() -> Vec<ModuleDescriptor> {
    vec![
        environment::descriptor(),
        forensics::descriptor(),
        processes::descriptor(),
    ]
}

pub fn run(id: u8) -> Result<ModuleReport> {
    match id {
        1 => environment::run(),
        2 => forensics::run(),
        3 => processes::run(),
        _ => bail!("unknown module id: {id}"),
    }
}
