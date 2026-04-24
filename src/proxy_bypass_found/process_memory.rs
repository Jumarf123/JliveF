use super::*;

pub(super) fn detect_process_memory(findings: &mut Vec<Finding>) {
    let mut system = System::new_all();
    system.refresh_processes();

    let mut module_hits = Vec::new();
    let mut memory_hits = Vec::new();

    for process in system.processes().values() {
        let name = process.name();
        if !name.eq_ignore_ascii_case("explorer.exe") {
            continue;
        }
        let pid = process.pid().as_u32();

        if let Ok(modules) = list_process_modules(pid) {
            for module in modules {
                let lower = module.path.to_string_lossy().to_lowercase();
                if lower.contains("future_hook_x32.dll") || lower.contains("future_hook_x64.dll") {
                    module_hits.push(format!(
                        "PID {} {} loaded module {}",
                        pid,
                        name,
                        module.path.display()
                    ));
                }
            }
        }

        let patterns: &[(&str, &[u8])] = &[
            ("future_hook_x64.dll", b"future_hook_x64.dll"),
            ("future_hook_x32.dll", b"future_hook_x32.dll"),
            ("xameleon.net", b"xameleon.net"),
            ("v4apollo.ru", b"v4apollo.ru"),
            ("PatchThenInject", b"PatchThenInject"),
            ("GLFW30", b"GLFW30"),
            ("Shell_TrayWnd", b"Shell_TrayWnd"),
        ];

        if let Ok(hits) = scan_process_for_strings(pid, patterns, 384 * 1024 * 1024) {
            let high_hits = hits
                .iter()
                .filter(|h| {
                    h.contains("future_hook") || h.contains("xameleon") || h.contains("v4apollo")
                })
                .cloned()
                .collect::<Vec<_>>();
            if !high_hits.is_empty() {
                memory_hits.push(format!(
                    "PID {} {} memory strings: {}",
                    pid,
                    name,
                    high_hits.join(", ")
                ));
            }
        }
    }

    if !module_hits.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "process_memory".to_string(),
            title: "explorer.exe has future_hook loaded as a module".to_string(),
            details: module_hits,
        });
    }
    if !memory_hits.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "process_memory".to_string(),
            title: "explorer.exe memory contains future_hook/xameleon injection strings"
                .to_string(),
            details: memory_hits,
        });
    }
}

pub(super) fn detect_minecraft_process_memory(
    findings: &mut Vec<Finding>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
) {
    let mut active_pids =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports)
            .into_iter()
            .map(|flow| flow.pid)
            .collect::<HashSet<_>>();
    active_pids.extend(collect_local_proxy_relay_pids(
        process_map,
        netstat_entries,
        minecraft_ports,
    ));
    if active_pids.is_empty() {
        return;
    }

    let patterns: &[(&str, &[u8])] = &[
        ("net.java.faker.Proxy", b"net.java.faker.Proxy"),
        ("net/java/faker/Proxy", b"net/java/faker/Proxy"),
        ("HttpHostSpoofer", b"HttpHostSpoofer"),
        ("allowDirectConnection", b"allowDirectConnection"),
        ("routerSpoof", b"routerSpoof"),
        ("tracerouteFix", b"tracerouteFix"),
        ("redirectStart", b"redirectStart"),
        ("redirect_start", b"redirect_start"),
        ("enable_ttl_fix", b"enable_ttl_fix"),
        ("ttl_paththrough", b"ttl_paththrough"),
        ("ttl_override", b"ttl_override"),
        ("binded_port", b"binded_port"),
        ("blockTraffic", b"blockTraffic"),
        ("setBlockTraffic", b"setBlockTraffic"),
        ("startProxy", b"startProxy"),
        ("127.0.0.1:25565", b"127.0.0.1:25565"),
        ("localhost:25565", b"localhost:25565"),
        ("localhost:80", b"localhost:80"),
        ("127.0.0.2", b"127.0.0.2"),
    ];

    let mut details = Vec::new();
    for pid in active_pids {
        let Some(process) = process_map.get(&pid) else {
            continue;
        };
        if let Ok(hits) = scan_process_for_strings(pid, patterns, 512 * 1024 * 1024) {
            let mut unique_hits = normalize_faker_memory_hits(hits);
            unique_hits.sort();
            unique_hits.dedup();
            if unique_hits.len() >= MIN_FAKER_MEMORY_STRING_HITS {
                details.push(format!(
                    "PID {} {} memory strings ({} hits): {}",
                    pid,
                    process.name,
                    unique_hits.len(),
                    unique_hits.join(", ")
                ));
            }
        }
    }

    if !details.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "minecraft_process_memory".to_string(),
            title: "Minecraft client/relay memory contains faker-specific strings".to_string(),
            details,
        });
    }
}

pub(super) fn normalize_faker_memory_hits(hits: Vec<String>) -> Vec<String> {
    hits.into_iter()
        .filter(|hit| {
            hit.contains("net.java.faker")
                || hit.contains("HttpHostSpoofer")
                || hit.contains("allowDirectConnection")
                || hit.contains("routerSpoof")
                || hit.contains("tracerouteFix")
                || hit.contains("redirectStart")
                || hit.contains("redirect_start")
                || hit.contains("enable_ttl_fix")
                || hit.contains("ttl_paththrough")
                || hit.contains("ttl_override")
                || hit.contains("binded_port")
                || hit.contains("blockTraffic")
                || hit.contains("setBlockTraffic")
                || hit.contains("startProxy")
                || hit.contains("127.0.0.1:25565")
                || hit.contains("localhost:25565")
                || hit.contains("localhost:80")
                || hit.contains("127.0.0.2")
        })
        .collect()
}

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

fn open_process_for_query(pid: u32) -> Result<HandleGuard> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_FLAGS, false, pid)? };
    HandleGuard::new(handle).context("OpenProcess failed")
}

fn list_process_modules(pid: u32) -> Result<Vec<ModuleInfo>> {
    enum_modules_with_psapi(pid).or_else(|_| enum_modules_with_toolhelp(pid))
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
        results.push(ModuleInfo {
            path: PathBuf::from(OsString::from_wide(&buffer)),
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
            results.push(ModuleInfo { path });
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
    Some(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

fn scan_process_for_strings(
    pid: u32,
    patterns: &[(&str, &[u8])],
    max_bytes: usize,
) -> Result<Vec<String>> {
    let handle = open_process_for_query(pid)?;
    let mut current = 0usize;
    let mut scanned = 0usize;
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let max_pattern_len = patterns.iter().map(|(_, p)| p.len()).max().unwrap_or(1);

    while scanned < max_bytes {
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

        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let mut offset = region_base;
            let mut carry = Vec::new();
            while offset < region_end && scanned < max_bytes {
                let remaining = region_end - offset;
                let chunk_size = remaining.min(1024 * 1024).min(max_bytes - scanned);
                if chunk_size == 0 {
                    break;
                }
                if let Ok(buffer) = read_bytes(handle.raw(), offset, chunk_size) {
                    let mut haystack = carry.clone();
                    haystack.extend_from_slice(&buffer);
                    for (name, pattern) in patterns {
                        if !seen.contains(*name)
                            && contains_ascii_case_insensitive(&haystack, pattern)
                        {
                            seen.insert((*name).to_string());
                            hits.push((*name).to_string());
                        }
                    }
                    let keep = max_pattern_len.saturating_sub(1).min(haystack.len());
                    carry = haystack[haystack.len() - keep..].to_vec();
                }
                scanned = scanned.saturating_add(chunk_size);
                offset = offset.saturating_add(chunk_size.max(1));
                if hits.len() == patterns.len() {
                    return Ok(hits);
                }
            }
        }

        if region_end <= current {
            break;
        }
        current = region_end;
    }

    Ok(hits)
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

pub(super) fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}
