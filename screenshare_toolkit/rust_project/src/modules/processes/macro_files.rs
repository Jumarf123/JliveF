use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

use crate::core::paths::{boot_time_local, expand_env};
use crate::core::report::ModuleReport;
use crate::core::time::{format_datetime, system_time_to_local};

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let username = env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let paths = macro_paths(&username);

    for path in paths {
        inspect_macro_path(report, &path)?;
    }

    scan_folder_extension(
        report,
        &expand_env(r"C:\Blackweb Gaming AP\config"),
        ".MA32AIY",
    )?;
    scan_folder_extension(
        report,
        &expand_env(r"C:\ProgramData\Alienware\AlienWare Command Center\fxmetadata"),
        ".json",
    )?;
    scan_folder_extension(
        report,
        &expand_env(r"C:\Program Files (x86)\MotoSpeed Gaming Mouse\V60\modules\setting"),
        ".bin",
    )?;
    scan_folder_extension(
        report,
        &expand_env(r"C:\Users\%USERNAME%\Documents\M711 Gaming Mouse"),
        "macro.db",
    )?;
    scan_folder_extension(
        report,
        &expand_env(r"C:\Users\%USERNAME%\Documents\ASUS\ROG\ROG Armoury\common\macro"),
        ".GMAC",
    )?;

    scan_file_for_pattern(
        report,
        &expand_env(r"C:\Users\%USERNAME%\AppData\Local\Razer\Synapse\log\macros\MacrosRazer3.txt"),
        "MacroClient:Delete",
        "Razer deleted macro trace",
    )?;
    scan_file_for_pattern(
        report,
        &expand_env(r"C:\ProgramData\Razer\Synapse3\LogSynapseService.log"),
        "turbo: true",
        "Razer turbo trace",
    )?;
    scan_file_for_pattern(
        report,
        &expand_env(r"C:\Users\%USERNAME%\AppData\Local\LGHUB\settings.db"),
        "\"durationMs\":",
        "Logitech macro trace",
    )?;
    scan_file_for_pattern(
        report,
        &expand_env(r"C:\Users\%USERNAME%\AppData\Local\LGHUB\settings.db-wal"),
        "\"durationMs\":",
        "Logitech macro trace",
    )?;

    Ok(())
}

fn macro_paths(username: &str) -> Vec<PathBuf> {
    [
        r"%APPDATA%\Local\BY-COMBO2",
        r"C:\Users\%USERNAME%\AppData\Local\Razer\Synapse3\Log\Razer Synapse 3.log",
        r"C:\Users\%USERNAME%\AppData\Local\LGHUB\settings.db",
        r"C:\Users\%USERNAME%\AppData\Local\LGHUB\settings.db-wal",
        r"C:\Users\%USERNAME%\AppData\Roaming\steelseries-engine-3-client\Session Storage\000003.log",
        r"C:\Program Files\AYAX GamingMouse\record.ini",
        r"C:\Program Files\Gaming MouseV30\record.ini",
        r"%APPDATA%\Local\BY-COMBO\curid.dct",
        r"%APPDATA%\Local\BY-COMBO\pro.dct",
        r"C:\Program Files (x86)\Bloody7\Bloody7\UserLog\Mouse\TLcir_9EFF3FF4\language\Settings\EnvironmentVar.ini",
        r"C:\ProgramData\Glorious Core\userdata\%USERNAME%\data\MacroDB.db",
        r"C:\ProgramData\Glorious Core\userdata\%USERNAME%\data\DeviceDB.db",
        r"C:\Program Files (x86)\KROM KOLT\Config\sequence.dat",
        r"C:\Program Files (x86)\SPC Gear",
        r"C:\Users\%USERNAME%\AppData\Roaming\ROCCAT\SWARM\macro\macro_list.dat",
        r"C:\Users\%USERNAME%\AppData\Roaming\ROCCAT\SWARM\macro\custom_macro_list.dat",
        r"C:\Users\%USERNAME%\AppData\Roaming\REDRAGON\GamingMouse",
        r"C:\Users\%USERNAME%\AppData\Roaming\REDRAGON\GamingMouse\macro.ini",
        r"C:\Users\%USERNAME%\AppData\Roaming\REDRAGON\GamingMouse\config.ini",
        r"C:\Program Files (x86)\AJ390R Gaming Mouse\data",
        r"C:\Program Files (x86)\Xenon200\Configs",
        r"C:\Program Files (x86)\FANTECH VX7 Gaming Mouse\config.ini",
        r"C:\Users\%USERNAME%\AppData\Local\BY-8801-GM917-v108\curid.dct",
        r"C:\Users\%USERNAME%\AppData\Local\BY-8801-GM917-v108\pro.dct",
    ]
    .iter()
    .map(|value| expand_env(&value.replace("%USERNAME%", username)))
    .collect()
}

fn inspect_macro_path(report: &mut ModuleReport, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    let modified = metadata.modified().ok().map(system_time_to_local);
    let readonly = metadata.permissions().readonly();
    let boot_time = boot_time_local();

    if let Some(modified) = modified {
        let severity = if modified > boot_time {
            "after boot"
        } else {
            "before boot"
        };
        report.add_warning(
            format!("Macro artifact found: {}", path.display()),
            format!("Last modified: {} ({severity})", format_datetime(&modified)),
        );
    }

    if readonly {
        report.add_warning(
            format!("Readonly macro artifact {}", path.display()),
            "The file or directory is marked read-only.",
        );
    }

    Ok(())
}

fn scan_folder_extension(report: &mut ModuleReport, folder: &Path, suffix: &str) -> Result<()> {
    if !folder.exists() {
        return Ok(());
    }

    for entry in WalkDir::new(folder).max_depth(1).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy())
            .unwrap_or_default();
        if name.ends_with(suffix) {
            inspect_macro_path(report, path)?;
        }
    }

    Ok(())
}

fn scan_file_for_pattern(
    report: &mut ModuleReport,
    path: &Path,
    pattern: &str,
    label: &str,
) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let content = fs::read(path).unwrap_or_default();
    if contains_ascii_bytes(&content, pattern) {
        report.add_warning(label, format!("Found `{pattern}` in {}", path.display()));
    }

    Ok(())
}

fn contains_ascii_bytes(bytes: &[u8], pattern: &str) -> bool {
    let needle = pattern.as_bytes();
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}
