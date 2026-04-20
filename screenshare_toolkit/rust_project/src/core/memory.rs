use std::mem::size_of;

use anyhow::Result;
use once_cell::sync::OnceCell;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, VirtualQueryEx,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows::core::PCWSTR;

const DEFAULT_MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;
const DEFAULT_OVERLAP: usize = 4096;
const MIN_ASCII_LEN: usize = 6;
const MIN_UTF16_LEN: usize = 4;
static DEBUG_PRIVILEGE: OnceCell<()> = OnceCell::new();

pub fn dump_process_strings(pid: u32) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    visit_process_strings(pid, |line| {
        strings.push(line.to_string());
        Ok(())
    })?;
    Ok(strings)
}

pub fn visit_process_strings(pid: u32, mut visitor: impl FnMut(&str) -> Result<()>) -> Result<()> {
    let _ = DEBUG_PRIVILEGE.get_or_try_init(enable_debug_privilege);
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )?
    };
    let result = visit_process_strings_from_handle(handle, &mut visitor);
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn visit_process_strings_from_handle(
    handle: windows::Win32::Foundation::HANDLE,
    visitor: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let mut address = 0usize;
    let mut scanned = 0usize;
    let mut previous_tail = Vec::new();

    while scanned < DEFAULT_MAX_SCAN_BYTES {
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
        ) && (protect & PAGE_GUARD) != PAGE_GUARD
            && (protect & PAGE_NOACCESS) != PAGE_NOACCESS;

        if mbi.State == MEM_COMMIT && readable {
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            let mut offset = 0usize;

            while offset < region_size && scanned < DEFAULT_MAX_SCAN_BYTES {
                let to_read = DEFAULT_CHUNK_SIZE.min(region_size - offset);
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

                if ok && bytes_read != 0 {
                    let mut combined = previous_tail.clone();
                    combined.extend_from_slice(&buffer[..bytes_read]);
                    for line in extract_ascii_strings(&combined) {
                        visitor(&line)?;
                    }
                    for line in extract_utf16_strings(&combined) {
                        visitor(&line)?;
                    }

                    let keep = DEFAULT_OVERLAP.min(combined.len());
                    previous_tail = combined[combined.len().saturating_sub(keep)..].to_vec();
                }

                offset += to_read;
                scanned += to_read;
            }
        }

        address = mbi.BaseAddress as usize + mbi.RegionSize;
    }

    Ok(())
}

fn extract_ascii_strings(bytes: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for byte in bytes {
        if is_ascii_memory_char(*byte) {
            current.push(*byte);
            continue;
        }

        flush_ascii(&mut result, &mut current);
    }

    flush_ascii(&mut result, &mut current);
    result
}

fn flush_ascii(result: &mut Vec<String>, current: &mut Vec<u8>) {
    if current.len() >= MIN_ASCII_LEN {
        result.push(String::from_utf8_lossy(current).trim().to_string());
    }
    current.clear();
}

fn extract_utf16_strings(bytes: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    for offset in [0usize, 1usize] {
        let mut current = Vec::new();
        let mut index = offset;
        while index + 1 < bytes.len() {
            let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
            if let Some(ch) = char::from_u32(unit as u32)
                && is_unicode_memory_char(ch)
            {
                current.push(unit);
                index += 2;
                continue;
            }

            flush_utf16(&mut result, &mut current);
            index += 2;
        }

        flush_utf16(&mut result, &mut current);
    }

    result
}

fn flush_utf16(result: &mut Vec<String>, current: &mut Vec<u16>) {
    if current.len() >= MIN_UTF16_LEN {
        result.push(String::from_utf16_lossy(current).trim().to_string());
    }
    current.clear();
}

fn is_ascii_memory_char(byte: u8) -> bool {
    matches!(byte, b' '..=b'~' | b'\t')
}

fn is_unicode_memory_char(ch: char) -> bool {
    !ch.is_control() && ch != '\u{fffd}'
}

fn enable_debug_privilege() -> Result<()> {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;
    }

    let mut luid = Default::default();
    let privilege_name = to_wide("SeDebugPrivilege");
    unsafe {
        LookupPrivilegeValueW(None, PCWSTR(privilege_name.as_ptr()), &mut luid)?;
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        AdjustTokenPrivileges(token, false, Some(&privileges), 0, None, None)?;
        let _ = CloseHandle(token);
    }

    Ok(())
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
