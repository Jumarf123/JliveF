mod bam;
mod journal;
mod scheduler;

use std::thread;
use std::time::Instant;

use anyhow::Result;

use crate::core::report::{ModuleDescriptor, ModuleReport};

pub fn descriptor() -> ModuleDescriptor {
    ModuleDescriptor {
        id: 2,
        label: "Disk and Journal Forensics",
        summary: "",
    }
}

pub fn run() -> Result<ModuleReport> {
    let mut report = ModuleReport::new(descriptor());
    let descriptor = descriptor();
    let trace = std::env::var("RUST_PROJECT_TRACE")
        .map(|value| value == "1")
        .unwrap_or(false);

    let bam_handle = thread::spawn(move || -> Result<ModuleReport> {
        let started = Instant::now();
        if trace {
            eprintln!("[trace] module2 BAM started");
        }
        let mut partial = ModuleReport::new(descriptor);
        bam::run(&mut partial)?;
        if trace {
            eprintln!(
                "[trace] module2 BAM finished in {:.2}s",
                started.elapsed().as_secs_f64()
            );
        }
        Ok(partial)
    });
    let journal_handle = thread::spawn(move || -> Result<ModuleReport> {
        let started = Instant::now();
        if trace {
            eprintln!("[trace] module2 USN started");
        }
        let mut partial = ModuleReport::new(descriptor);
        journal::run(&mut partial)?;
        if trace {
            eprintln!(
                "[trace] module2 USN finished in {:.2}s",
                started.elapsed().as_secs_f64()
            );
        }
        Ok(partial)
    });
    let scheduler_handle = thread::spawn(move || -> Result<ModuleReport> {
        let started = Instant::now();
        if trace {
            eprintln!("[trace] module2 Scheduler started");
        }
        let mut partial = ModuleReport::new(descriptor);
        scheduler::run(&mut partial)?;
        if trace {
            eprintln!(
                "[trace] module2 Scheduler finished in {:.2}s",
                started.elapsed().as_secs_f64()
            );
        }
        Ok(partial)
    });

    report.merge(
        bam_handle
            .join()
            .map_err(|_| anyhow::anyhow!("BAM worker panicked"))??,
    );
    report.merge(
        journal_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Journal worker panicked"))??,
    );
    report.merge(
        scheduler_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Scheduler worker panicked"))??,
    );

    Ok(report.finish())
}
