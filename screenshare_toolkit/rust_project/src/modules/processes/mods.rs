use std::path::PathBuf;

use anyhow::Result;
use walkdir::WalkDir;

use crate::core::paths::expand_env;
use crate::core::report::ModuleReport;
use crate::core::time::{format_datetime, parse_powershell_datetime, system_time_to_local};

use super::memory_tool;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let processes = memory_tool::get_started_processes(&["javaw.exe", "Minecraft.Windows.exe"])?;
    if processes.is_empty() {
        return Ok(());
    }

    let mods_dir = expand_env(r"%APPDATA%\.minecraft\mods");
    if !mods_dir.exists() {
        return Ok(());
    }

    for process in processes {
        let Some(start_time) = process
            .StartTime
            .as_deref()
            .and_then(parse_powershell_datetime)
        else {
            continue;
        };

        for entry in WalkDir::new(&mods_dir).max_depth(1).into_iter().flatten() {
            let path: PathBuf = entry.path().to_path_buf();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("jar") {
                continue;
            }

            let modified = std::fs::metadata(&path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .map(system_time_to_local);

            if let Some(modified) = modified
                && modified > start_time
            {
                report.add_warning(
                    format!(
                        "Mod modified after game start: {}",
                        path.file_name()
                            .map(|value| value.to_string_lossy())
                            .unwrap_or_default()
                    ),
                    format!(
                        "Process={} StartTime={} FileModified={}",
                        process.Name.clone().unwrap_or_default(),
                        format_datetime(&start_time),
                        format_datetime(&modified)
                    ),
                );
            }
        }
    }

    Ok(())
}
