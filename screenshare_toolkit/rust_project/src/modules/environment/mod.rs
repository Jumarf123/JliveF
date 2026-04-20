mod admin;
mod devices;
mod disks;
mod eventlog;
mod network;
mod services;
mod system_informer;
mod vm;

use std::thread;

use anyhow::Result;

use crate::core::report::{ModuleDescriptor, ModuleReport};

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        id: 1,
        label: "Environment and Devices",
        summary: "",
    }
}

pub fn run() -> Result<ModuleReport> {
    let mut report = ModuleReport::new(descriptor());
    let descriptor = descriptor();

    let admin_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        admin::run(&mut partial)?;
        Ok(partial)
    });
    let vm_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        vm::run(&mut partial)?;
        Ok(partial)
    });
    let devices_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        devices::run(&mut partial)?;
        Ok(partial)
    });
    let network_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        network::run(&mut partial)?;
        Ok(partial)
    });
    let eventlog_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        eventlog::run(&mut partial)?;
        Ok(partial)
    });
    let disks_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        disks::run(&mut partial)?;
        Ok(partial)
    });
    let system_informer_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        system_informer::run(&mut partial)?;
        Ok(partial)
    });
    let services_handle = thread::spawn(move || -> Result<ModuleReport> {
        let mut partial = ModuleReport::new(descriptor);
        services::run(&mut partial)?;
        Ok(partial)
    });

    report.merge(
        admin_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Admin worker panicked"))??,
    );
    report.merge(
        vm_handle
            .join()
            .map_err(|_| anyhow::anyhow!("VM worker panicked"))??,
    );
    report.merge(
        devices_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Devices worker panicked"))??,
    );
    report.merge(
        network_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Network worker panicked"))??,
    );
    report.merge(
        eventlog_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Eventlog worker panicked"))??,
    );
    report.merge(
        disks_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Disk worker panicked"))??,
    );
    report.merge(
        system_informer_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Prefetch worker panicked"))??,
    );
    report.merge(
        services_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Services worker panicked"))??,
    );

    Ok(report.finish())
}
