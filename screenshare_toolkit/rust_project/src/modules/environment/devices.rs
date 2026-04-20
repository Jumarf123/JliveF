use anyhow::Result;
use serde::Deserialize;
use std::collections::HashSet;

use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, FILETIME};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, RegCloseKey, RegEnumKeyExW, RegOpenKeyExW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::core::parsers::extract_vid_pid;
use crate::core::report::ModuleReport;
use crate::core::shell::{run_powershell, run_powershell_json_array};
use crate::core::time::{filetime_to_local, format_datetime, parse_powershell_datetime};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct DeviceEntry {
    DeviceID: Option<String>,
    InstanceId: Option<String>,
    PNPDeviceID: Option<String>,
    Status: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    scan_mouse_keys(report)?;
    scan_mice(report)?;
    scan_unplugged_devices(report)?;
    scan_usb_topology(report)?;
    Ok(())
}

fn scan_mouse_keys(report: &mut ModuleReport) -> Result<()> {
    let flags = run_powershell(
        "(Get-ItemProperty -Path 'HKCU:\\Control Panel\\Accessibility\\MouseKeys' -Name Flags -ErrorAction SilentlyContinue).Flags",
    )?;

    if flags.trim() == "63" {
        report.add_warning(
            "MouseKeys is enabled",
            "Review whether attack input is bound to a keyboard key instead of a mouse button.",
        );
    } else {
        report.add_info(
            "MouseKeys is disabled",
            "The MouseKeys Flags value is not set to 63.",
        );
    }

    Ok(())
}

fn scan_mice(report: &mut ModuleReport) -> Result<()> {
    let mut devices: Vec<DeviceEntry> = run_powershell_json_array(
        "Get-CimInstance Win32_PointingDevice -ErrorAction SilentlyContinue | \
         Select-Object Name, DeviceID, PNPDeviceID",
    )?;

    if devices.is_empty() {
        devices = run_powershell_json_array(
            "Get-PnpDevice -Class Mouse -PresentOnly -ErrorAction SilentlyContinue | \
             Select-Object FriendlyName, InstanceId, Status",
        )?;
    }

    let mut mouse_count = 0usize;
    for device in devices {
        let raw_id = device
            .DeviceID
            .clone()
            .or(device.PNPDeviceID.clone())
            .or(device.InstanceId.clone());

        if let Some(device_id) = raw_id
            && let Some((vid, pid)) = extract_vid_pid(&device_id)
        {
            report.add_info(
                "Mouse device",
                format!("VID={vid}, PID={pid}, DeviceID={device_id}"),
            );
            mouse_count += 1;
        }
    }

    if mouse_count >= 2 {
        report.add_warning(
            "Multiple mice detected",
            format!(
                "At least {mouse_count} mouse devices with VID/PID were found. Review Bluetooth & devices."
            ),
        );
    }

    Ok(())
}

fn scan_usb_topology(report: &mut ModuleReport) -> Result<()> {
    let devices: Vec<DeviceEntry> = run_powershell_json_array(
        "Get-CimInstance Win32_PnPEntity | \
         Where-Object { $_.PNPClass -eq 'USB' -or $_.DeviceID -like 'USB\\\\*' } | \
         Select-Object Name, DeviceID, Status",
    )?;

    if !devices.is_empty() {
        let count = devices.len();
        let list = devices
            .into_iter()
            .take(5)
            .filter_map(|device| {
                let id = device.DeviceID?;
                Some(format!(
                    "  - {} (Status={})",
                    id,
                    device.Status.unwrap_or_else(|| "Unknown".to_string())
                ))
            })
            .collect::<Vec<_>>();

        report.add_info(
            "USB topology captured",
            format!("Found {count} USB devices.\n{}", list.join("\n")),
        );
    }

    Ok(())
}

fn scan_unplugged_devices(report: &mut ModuleReport) -> Result<()> {
    let Some(last_logon) = get_last_interactive_logon()? else {
        return Ok(());
    };

    let root = open_hklm_subkey(r"SYSTEM\ControlSet001\Enum\USB")?;
    let vendor_keys = enum_subkeys(root)?;
    let mut flagged = HashSet::new();

    for (vendor, _) in vendor_keys {
        let vendor_path = format!(r"SYSTEM\ControlSet001\Enum\USB\{vendor}");
        let vendor_key = match open_hklm_subkey(&vendor_path) {
            Ok(handle) => handle,
            Err(_) => continue,
        };

        for (instance, last_write) in enum_subkeys(vendor_key)? {
            let full = format!(r"{vendor}\{instance}");
            let dedup = full.chars().take(17).collect::<String>();
            let local = filetime_to_local(last_write);
            let delta = (local - last_logon).num_seconds();

            if delta > 10 && flagged.insert(dedup) {
                report.add_warning(
                    "Unplugged USB device trace",
                    format!(
                        "{} modified at {} after last logon {}",
                        full,
                        format_datetime(&local),
                        format_datetime(&last_logon)
                    ),
                );
            }
        }

        unsafe {
            let _ = RegCloseKey(vendor_key);
        }
    }

    unsafe {
        let _ = RegCloseKey(root);
    }
    Ok(())
}

fn get_last_interactive_logon() -> Result<Option<chrono::DateTime<chrono::Local>>> {
    let output = run_powershell(
        "$value = Get-CimInstance Win32_LogonSession | \
         Where-Object { $_.LogonType -eq 2 } | \
         Sort-Object StartTime -Descending | \
         Select-Object -First 1 -ExpandProperty StartTime; \
         if ($value) { try { $value.ToString('o') } catch { $value.ToString() } }",
    )?;

    Ok(parse_powershell_datetime(output.trim()))
}

fn open_hklm_subkey(path: &str) -> Result<HKEY> {
    let mut handle = HKEY::default();
    let wide = to_wide(path);
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            Some(0),
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };

    if status.0 != 0 {
        anyhow::bail!("RegOpenKeyExW failed for {path} with {}", status.0);
    }

    Ok(handle)
}

fn enum_subkeys(key: HKEY) -> Result<Vec<(String, FILETIME)>> {
    let mut entries = Vec::new();
    let mut index = 0u32;

    loop {
        let mut name = vec![0u16; 512];
        let mut len = name.len() as u32;
        let mut last_write = FILETIME::default();

        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                Some(&mut last_write),
            )
        };

        if status == ERROR_NO_MORE_ITEMS {
            break;
        }

        if status.0 == 0 {
            entries.push((String::from_utf16_lossy(&name[..len as usize]), last_write));
        }

        index += 1;
    }

    Ok(entries)
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
