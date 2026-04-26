mod hotspot;
mod win32;

use self::hotspot::HotspotDumper;
use anyhow::{Context, Result, anyhow};
use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};

const WARNING_PREVIEW_LIMIT: usize = 10;

pub fn run_for_pid(pid: u32) -> Result<PathBuf> {
    println!("External dumper: attaching to PID {pid}...");

    let dumper = HotspotDumper::attach(pid)
        .with_context(|| format!("attaching external dumper to pid {pid}"))?;
    let report = dumper.dump().context("dumping HotSpot classes")?;
    let output_path = build_output_path(pid)?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating output dir {}", parent.display()))?;
    }

    fs::write(&output_path, report.render())
        .with_context(|| format!("writing dump to {}", output_path.display()))?;

    println!("Classes dumped: {}", report.classes.len());
    if !report.warnings.is_empty() {
        println!("Warnings: {}", report.warnings.len());
        for warning in report.warnings.iter().take(WARNING_PREVIEW_LIMIT) {
            println!("  - {warning}");
        }
        if report.warnings.len() > WARNING_PREVIEW_LIMIT {
            println!("  - ...");
        }
    }
    println!("Output: {}", output_path.display());

    Ok(output_path)
}

fn build_output_path(pid: u32) -> Result<PathBuf> {
    let exe_dir = std::env::current_exe()
        .context("resolving current exe path")?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Could not resolve executable directory"))?;
    let output_dir = exe_dir.join("results").join("dumper").join("external");
    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    Ok(output_dir.join(format!("external_classes_{}_{}.txt", pid, timestamp)))
}
