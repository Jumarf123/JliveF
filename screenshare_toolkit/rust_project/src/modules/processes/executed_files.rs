use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Result;

use crate::core::parsers::{extract_windows_paths, normalize_explorer_uri};
use crate::core::report::ModuleReport;
use crate::core::signatures::is_trusted;

use super::memory_tool;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    scan_explorer(report)?;
    scan_service_memory(report, "PlugPlay")?;
    scan_service_memory(report, "PcaSvc")?;

    Ok(())
}

fn scan_explorer(report: &mut ModuleReport) -> Result<()> {
    let processes = memory_tool::get_processes_by_names(&["explorer.exe"])?;
    let Some(pid) = processes.first().and_then(|process| process.ProcessId) else {
        return Ok(());
    };

    let output = memory_tool::scan_pid(pid)?;
    let mut seen = HashSet::new();

    for line in output.lines() {
        let Some(path) = normalize_explorer_uri(line) else {
            continue;
        };

        if !seen.insert(path.clone()) {
            continue;
        }

        report_executable_path(report, "Explorer accessed file", path)?;
    }

    Ok(())
}

fn scan_service_memory(report: &mut ModuleReport, service_name: &str) -> Result<()> {
    let Some(pid) = memory_tool::get_service_pid(service_name)? else {
        report.add_warning(
            format!("Service {service_name} was not found"),
            "The expected service instance was not available for the memory scan.",
        );
        return Ok(());
    };

    let output = memory_tool::scan_pid(pid)?;
    let mut seen = HashSet::new();

    for line in output.lines() {
        for path in extract_windows_paths(line) {
            if is_noise_path(&path) {
                continue;
            }
            if seen.insert(path.clone()) {
                report_executable_path(
                    report,
                    &format!("{service_name} executed path"),
                    PathBuf::from(path),
                )?;
            }
        }
    }

    Ok(())
}

fn report_executable_path(report: &mut ModuleReport, label: &str, path: PathBuf) -> Result<()> {
    if is_noise_path(&path.to_string_lossy()) {
        return Ok(());
    }

    if path.exists() {
        if !is_trusted(&path)? {
            report.add_warning(
                label,
                format!("Unsigned or untrusted path: {}", path.display()),
            );
        }
    } else {
        report.add_warning(label, format!("Path no longer exists: {}", path.display()));
    }

    Ok(())
}

fn is_noise_path(path: &str) -> bool {
    let lowered = path.trim_matches('"').to_ascii_lowercase();
    lowered == r"c:\autoexec.bat"
        || lowered == r"c:\config.sys"
        || lowered.contains('*')
        || lowered.contains(';')
        || lowered.starts_with(r"c:\windows\microsoft.ui.xaml.controls\")
        || lowered.starts_with(r"c:\windows\system32\securityandmaintenance_")
}
