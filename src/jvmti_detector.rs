use std::ffi::{OsString, c_void};
use std::io::{self, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use sysinfo::System;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, ReadProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

const PROCESS_QUERY_FLAGS: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0);

const PATTERN_A: u32 = 524_294;
const PATTERN_B: u32 = 4_242_546_329;

pub fn run_detector_cli() -> Result<()> {
    let result = scan_targets()?;
    println!(
        "{}",
        if result.found {
            "Found jvmti injection"
        } else {
            "Not found"
        }
    );
    if !result.message.is_empty() {
        println!("{}", result.message);
    }
    Ok(())
}

struct ProcessInfo {
    pid: u32,
}

#[derive(Clone)]
struct ModuleInfo {
    handle: HMODULE,
    path: PathBuf,
}

struct DetectionResult {
    found: bool,
    message: String,
}

struct ProcessAnalysis {
    found: bool,
    message: String,
}

fn scan_targets() -> Result<DetectionResult> {
    let processes = find_javaw_processes();
    if processes.is_empty() {
        let pid = prompt_for_pid("javaw.exe не найден. Введите PID процесса Minecraft: ")?;
        return scan_single_pid(pid);
    }

    let mut found = false;
    let mut messages = Vec::new();
    for process in processes {
        match analyze_process(process.pid) {
            Ok(Some(result)) => {
                if result.found {
                    found = true;
                }
                if !result.message.is_empty() {
                    messages.push(result.message);
                }
            }
            Ok(None) => {}
            Err(err) => {
                messages.push(format!("PID {}: ошибка проверки: {}", process.pid, err));
            }
        }
    }

    if !found && messages.is_empty() {
        messages.push("Паттерны JVMTI-инъекции не обнаружены".to_string());
    }

    Ok(DetectionResult {
        found,
        message: messages.join("\n\n"),
    })
}

fn scan_single_pid(pid: u32) -> Result<DetectionResult> {
    match analyze_process(pid) {
        Ok(Some(result)) => Ok(DetectionResult {
            found: result.found,
            message: result.message,
        }),
        Ok(None) => Ok(DetectionResult {
            found: false,
            message: format!("PID {pid}: jvm.dll не найден"),
        }),
        Err(err) => Ok(DetectionResult {
            found: false,
            message: format!("PID {pid}: ошибка проверки: {err}"),
        }),
    }
}

fn analyze_process(pid: u32) -> Result<Option<ProcessAnalysis>> {
    let modules = list_process_modules(pid)?;
    let handle = open_process_for_query(pid)?;

    let (base, size, jvm_path) = match find_jvm_image(&modules, &handle) {
        Some(range) => range,
        None => return Ok(None),
    };

    let hit_a = trace_dword(&handle, base, size, PATTERN_A);
    let hit_b = trace_dword(&handle, base, size, PATTERN_B);
    let prefix = format!("PID {} [{}]", pid, jvm_path.display());

    if let (Some(hit_a), Some(hit_b)) = (&hit_a, &hit_b) {
        let desc_a = format_hit("паттерн A", PATTERN_A, hit_a);
        let desc_b = format_hit("паттерн B", PATTERN_B, hit_b);
        Ok(Some(ProcessAnalysis {
            found: true,
            message: format!(
                "{prefix}: обнаружены сигнатуры JVMTI/JNI-инъекции\n{desc_a}\n{desc_b}"
            ),
        }))
    } else {
        Ok(Some(ProcessAnalysis {
            found: false,
            message: String::new(),
        }))
    }
}

fn prompt_for_pid(prompt: &str) -> Result<u32> {
    loop {
        print!("{prompt}");
        io::stdout().flush().ok();

        let mut input = String::new();
        let bytes_read = io::stdin().read_line(&mut input).context("reading PID")?;
        if bytes_read == 0 {
            return Err(anyhow!("PID input was closed"));
        }

        match input.trim().parse::<u32>() {
            Ok(pid) if pid != 0 => return Ok(pid),
            _ => println!("Введите корректный PID."),
        }
    }
}

fn find_javaw_processes() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_processes();

    system
        .processes()
        .values()
        .filter(|process| process.name().eq_ignore_ascii_case("javaw.exe"))
        .map(|process| ProcessInfo {
            pid: process.pid().as_u32(),
        })
        .collect()
}

fn open_process_for_query(pid: u32) -> Result<HandleGuard> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_FLAGS, false, pid)? };
    HandleGuard::new(handle).context("OpenProcess failed")
}

fn list_process_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    enum_modules_with_psapi(pid).or_else(|_| enum_modules_with_toolhelp(pid))
}

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_invalid() {
            bail!("invalid handle");
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn enum_modules_with_psapi(pid: u32) -> Result<Vec<ModuleInfo>> {
    let handle = open_process_for_query(pid)?;

    let mut needed_bytes: u32 = 0;
    unsafe {
        EnumProcessModulesEx(
            handle.raw(),
            std::ptr::null_mut(),
            0,
            &mut needed_bytes,
            LIST_MODULES_ALL,
        )?;
    }

    if needed_bytes == 0 {
        bail!("no module data returned");
    }

    let module_count = (needed_bytes as usize) / std::mem::size_of::<HMODULE>();
    let mut modules = vec![HMODULE(0); module_count];
    unsafe {
        EnumProcessModulesEx(
            handle.raw(),
            modules.as_mut_ptr(),
            needed_bytes,
            &mut needed_bytes,
            LIST_MODULES_ALL,
        )?;
    }

    let mut results = Vec::new();
    for module in modules {
        let mut buffer = vec![0u16; 1024];
        let len = unsafe { GetModuleFileNameExW(handle.raw(), module, &mut buffer) };
        if len == 0 {
            continue;
        }
        buffer.truncate(len as usize);
        let os_string = OsString::from_wide(&buffer);
        results.push(ModuleInfo {
            handle: module,
            path: PathBuf::from(os_string),
        });
    }

    if results.is_empty() {
        bail!("no module paths read via PSAPI");
    }

    Ok(results)
}

fn enum_modules_with_toolhelp(pid: u32) -> Result<Vec<ModuleInfo>> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };
    if snapshot == INVALID_HANDLE_VALUE {
        bail!("CreateToolhelp32Snapshot failed");
    }
    let snapshot = HandleGuard::new(snapshot)?;

    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut results = Vec::new();
    let mut has_entry = unsafe { Module32FirstW(snapshot.raw(), &mut entry).is_ok() };
    while has_entry {
        if let Some(path) = wide_to_path(&entry.szExePath) {
            results.push(ModuleInfo {
                handle: entry.hModule,
                path,
            });
        }
        has_entry = unsafe { Module32NextW(snapshot.raw(), &mut entry).is_ok() };
    }

    if results.is_empty() {
        bail!("no module paths read via Toolhelp");
    }

    Ok(results)
}

fn wide_to_path(buffer: &[u16]) -> Option<PathBuf> {
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    if len == 0 {
        return None;
    }
    let os_string = OsString::from_wide(&buffer[..len]);
    Some(PathBuf::from(os_string))
}

fn find_jvm_image(modules: &[ModuleInfo], handle: &HandleGuard) -> Option<(usize, usize, PathBuf)> {
    let jvm_mod = modules.iter().find(|module| {
        module
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.eq_ignore_ascii_case("jvm.dll"))
            .unwrap_or(false)
    })?;

    let base = jvm_mod.handle.0 as usize;

    let mut dos_header = IMAGE_DOS_HEADER::default();
    if read_into(handle.raw(), base, &mut dos_header).is_err() || dos_header.e_magic != 0x5A4D {
        return None;
    }

    let nt_header_addr = base + dos_header.e_lfanew as usize;
    let mut nt_headers = IMAGE_NT_HEADERS64::default();
    if read_into(handle.raw(), nt_header_addr, &mut nt_headers).is_err() {
        return None;
    }

    let size = nt_headers.OptionalHeader.SizeOfImage as usize;
    if size == 0 {
        return None;
    }

    Some((base, size, jvm_mod.path.clone()))
}

fn read_into<T>(handle: HANDLE, address: usize, target: &mut T) -> Result<()> {
    let mut bytes_read: usize = 0;
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            target as *mut _ as *mut c_void,
            std::mem::size_of::<T>(),
            Some(&mut bytes_read),
        )?;
    }
    if bytes_read != std::mem::size_of::<T>() {
        bail!("short read");
    }
    Ok(())
}

#[derive(Clone)]
struct PatternHit {
    offset: usize,
}

fn trace_dword(handle: &HandleGuard, base: usize, size: usize, target: u32) -> Option<PatternHit> {
    let end = base.saturating_add(size);
    let mut current = base;

    while current < end {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let res = unsafe {
            VirtualQueryEx(
                handle.raw(),
                Some(current as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if res == 0 {
            break;
        }

        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;
        if region_size == 0 {
            break;
        }

        let region_end = region_base.saturating_add(region_size);
        let scan_start = region_base.max(base);
        let scan_end = region_end.min(end);

        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let mut offset = scan_start;
            while offset < scan_end {
                let remaining = scan_end - offset;
                let chunk = remaining.min(256 * 1024);
                if let Ok(buffer) = read_bytes(handle.raw(), offset, chunk) {
                    if let Some(hit) = find_dword(&buffer, target, offset - base) {
                        return Some(hit);
                    }
                }
                offset = offset.saturating_add(chunk.max(1));
            }
        }

        current = region_end;
    }

    None
}

fn read_bytes(handle: HANDLE, address: usize, len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; len];
    let mut bytes_read: usize = 0;
    unsafe {
        ReadProcessMemory(
            handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut bytes_read),
        )?;
    }
    buffer.truncate(bytes_read);
    Ok(buffer)
}

fn find_dword(data: &[u8], target: u32, base_offset: usize) -> Option<PatternHit> {
    if data.len() < 4 {
        return None;
    }

    let mut index = 0;
    while index + 4 <= data.len() {
        let value = u32::from_le_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]);
        if value == target {
            return Some(PatternHit {
                offset: base_offset + index,
            });
        }
        index += 4;
    }
    None
}

fn is_readable(protect: PAGE_PROTECTION_FLAGS) -> bool {
    let value = protect.0;
    if (value & PAGE_GUARD.0) != 0 || (value & PAGE_NOACCESS.0) != 0 {
        return false;
    }

    let readable_mask = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_EXECUTE_WRITECOPY.0;

    (value & readable_mask) != 0
}

fn format_hit(name: &str, value: u32, hit: &PatternHit) -> String {
    format!(
        "{}: DWORD {} (0x{:08X}) по смещению 0x{:X} внутри jvm.dll",
        name, value, value, hit.offset
    )
}
