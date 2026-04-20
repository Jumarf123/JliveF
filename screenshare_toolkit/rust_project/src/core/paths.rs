use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use regex::Regex;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::core::time::system_time_to_local;

pub fn current_exe_dir() -> Result<PathBuf> {
    let exe = env::current_exe().context("failed to resolve current executable path")?;
    exe.parent()
        .map(Path::to_path_buf)
        .context("failed to resolve executable parent directory")
}

pub fn results_dir() -> Result<PathBuf> {
    let directory = current_exe_dir()?.join("results");
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create output directory: {}", directory.display()))?;
    Ok(directory)
}

pub fn module_results_dir(module_id: u8, module_label: &str) -> Result<PathBuf> {
    let directory = results_dir()?.join(module_results_folder_name(module_id, module_label));
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create module directory: {}", directory.display()))?;
    Ok(directory)
}

pub fn module_results_folder_name(module_id: u8, module_label: &str) -> String {
    let mut slug = String::new();
    let mut last_was_separator = true;

    for ch in module_label.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_separator = false;
        } else if !last_was_separator {
            slug.push('_');
            last_was_separator = true;
        }
    }

    while slug.ends_with('_') {
        slug.pop();
    }

    if slug.is_empty() {
        format!("module_{module_id}")
    } else {
        format!("module_{module_id}_{slug}")
    }
}

pub fn expand_env(input: &str) -> PathBuf {
    let regex = Regex::new(r"%([A-Za-z0-9_]+)%").expect("env placeholder regex is valid");
    let expanded = regex.replace_all(input, |captures: &regex::Captures<'_>| {
        let key = captures
            .get(1)
            .map(|item| item.as_str())
            .unwrap_or_default();
        env::var(key).unwrap_or_else(|_| captures[0].to_string())
    });
    PathBuf::from(expanded.to_string())
}

pub fn normalize_windows_path(path: &str) -> PathBuf {
    PathBuf::from(path.replace('/', "\\"))
}

pub fn convert_device_path_to_dos(device_path: &str) -> Option<PathBuf> {
    convert_device_path_to_dos_with_map(device_path, &dos_device_map())
}

pub fn convert_device_path_to_dos_with_map(
    device_path: &str,
    map: &[(String, String)],
) -> Option<PathBuf> {
    for (drive, mapped) in map {
        if device_path.starts_with(mapped) {
            let suffix = &device_path[mapped.len()..];
            return Some(PathBuf::from(format!("{drive}{suffix}")));
        }
    }

    None
}

pub fn dos_device_map() -> Vec<(String, String)> {
    let mut result = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_wide = to_wide(&drive);
        let mut buffer = vec![0u16; 512];

        let length = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buffer)) };

        if length == 0 {
            continue;
        }

        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(length as usize);
        let mapped = String::from_utf16_lossy(&buffer[..end]);
        result.push((drive, mapped));
    }

    result
}

pub fn boot_time_local() -> chrono::DateTime<chrono::Local> {
    let uptime = Duration::from_millis(unsafe {
        windows::Win32::System::SystemInformation::GetTickCount64()
    });
    system_time_to_local(SystemTime::now() - uptime)
}

pub fn to_os_string_vec(items: &[impl AsRef<OsStr>]) -> Vec<OsString> {
    items
        .iter()
        .map(|item| item.as_ref().to_os_string())
        .collect()
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
