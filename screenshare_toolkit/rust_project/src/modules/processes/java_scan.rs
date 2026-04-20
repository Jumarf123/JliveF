use std::mem::size_of;

use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::core::report::ModuleReport;

const TARGET_NAMES: &[&str] = &["javaw.exe", "Minecraft.Windows.exe"];
const TARGET_PATTERN: &[u8] = b"Autoclicker.class";
const MAX_SCAN_BYTES_PER_PROCESS: usize = 64 * 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    if snapshot == INVALID_HANDLE_VALUE {
        report.add_warning(
            "Java process snapshot failed",
            "The process snapshot could not be created.",
        );
        return Ok(());
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found_any = false;
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };

    while has_entry {
        let process_name = wide_to_string(&entry.szExeFile);
        if TARGET_NAMES
            .iter()
            .any(|name| process_name.eq_ignore_ascii_case(name))
        {
            found_any = true;
            if let Some(hit) = scan_process(entry.th32ProcessID)? {
                report.add_warning(
                    format!("Minecraft/Java memory match in {}", process_name),
                    format!(
                        "PID {} contains `{}` in a readable private region. {}",
                        entry.th32ProcessID,
                        String::from_utf8_lossy(TARGET_PATTERN),
                        hit
                    ),
                );
            }
        }

        has_entry = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    if !found_any {
        report.add_info(
            "No Java or Minecraft process matched",
            "No javaw.exe or Minecraft.Windows.exe process was available for the Java memory scan.",
        );
    }

    Ok(())
}

fn scan_process(pid: u32) -> Result<Option<String>> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    let result = scan_handle(handle, pid);
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn scan_handle(handle: HANDLE, pid: u32) -> Result<Option<String>> {
    let mut address = 0usize;
    let mut scanned = 0usize;

    while scanned < MAX_SCAN_BYTES_PER_PROCESS {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }

        let protect = mbi.Protect;
        let readable = matches!(
            protect,
            PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
        );

        if mbi.State == MEM_COMMIT && readable {
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            let mut offset = 0usize;

            while offset < region_size && scanned < MAX_SCAN_BYTES_PER_PROCESS {
                let to_read = CHUNK_SIZE.min(region_size - offset);
                let mut buffer = vec![0u8; to_read];
                let mut bytes_read = 0usize;

                let ok = unsafe {
                    ReadProcessMemory(
                        handle,
                        (region_base + offset) as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        to_read,
                        Some(&mut bytes_read),
                    )
                    .is_ok()
                };

                if ok
                    && bytes_read >= TARGET_PATTERN.len()
                    && buffer[..bytes_read]
                        .windows(TARGET_PATTERN.len())
                        .any(|window| window == TARGET_PATTERN)
                {
                    return Ok(Some(format!(
                        "Read match at 0x{:X} while scanning PID {}",
                        region_base + offset,
                        pid
                    )));
                }

                offset += to_read;
                scanned += to_read;
            }
        }

        address = mbi.BaseAddress as usize + mbi.RegionSize;
    }

    Ok(None)
}

fn wide_to_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|char| *char == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}
