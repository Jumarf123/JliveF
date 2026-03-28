use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, c_void};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use std::{fs, time::SystemTime};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Local, TimeZone, Utc};
use regex::Regex;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sysinfo::System;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::core::PCWSTR;

use crate::bypass_scan::utils::run_powershell;

const SCRIPT_EXTS: &[&str] = &[
    "bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "py", "pyw", "js", "jse", "vbs", "vbe", "wsf",
    "wsh", "hta", "ahk", "lua", "rb", "pl", "php", "mjs", "cjs",
];

const SOURCE_EXTS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "cs", "java", "go", "rs", "kt", "kts", "ts", "tsx", "jsx",
];

const MEMORY_PROCESS_NAMES: &[&str] = &[
    "svchost.exe",
    "services.exe",
    "explorer.exe",
    "cmd.exe",
    "conhost.exe",
    "powershell.exe",
    "pwsh.exe",
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "node.exe",
    "java.exe",
    "javaw.exe",
];

const LIVE_PROCESS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
Where-Object { $_.Name -and $_.CommandLine } |
ForEach-Object {
  $createdUtc = ''
  if ($_.CreationDate) {
    try {
      $createdUtc = ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)).ToUniversalTime().ToString('o')
    } catch {}
  }
  [pscustomobject]@{
    processId = [int]$_.ProcessId
    name = [string]$_.Name
    createdUtc = $createdUtc
    executablePath = [string]$_.ExecutablePath
    commandLine = [string]$_.CommandLine
  }
} | ConvertTo-Json -Compress -Depth 4
"#;

const USERASSIST_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
function Invoke-Rot13([string]$text) {
  $chars = $text.ToCharArray()
  for ($i = 0; $i -lt $chars.Length; $i++) {
    $c = [int][char]$chars[$i]
    if ($c -ge 65 -and $c -le 90) {
      $chars[$i] = [char]((($c - 65 + 13) % 26) + 65)
    } elseif ($c -ge 97 -and $c -le 122) {
      $chars[$i] = [char]((($c - 97 + 13) % 26) + 97)
    }
  }
  -join $chars
}
$items = New-Object System.Collections.Generic.List[object]
$root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
if (Test-Path $root) {
  Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
    $guid = $_.PSChildName
    $countPath = Join-Path $_.PSPath 'Count'
    if (Test-Path $countPath) {
      try {
        $key = Get-Item -LiteralPath $countPath -ErrorAction Stop
        foreach ($valueName in $key.GetValueNames()) {
          $data = $key.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
          if (-not ($data -is [byte[]])) { continue }
          $lastRunUtc = ''
          if ($data.Length -ge 68) {
            try {
              $ft = [BitConverter]::ToInt64($data, 60)
              if ($ft -gt 0) {
                $lastRunUtc = [DateTime]::FromFileTimeUtc($ft).ToString('o')
              }
            } catch {}
          }
          $runCount = if ($data.Length -ge 8) { [BitConverter]::ToUInt32($data, 4) } else { 0 }
          $focusCount = if ($data.Length -ge 12) { [BitConverter]::ToUInt32($data, 8) } else { 0 }
          $focusTime = if ($data.Length -ge 16) { [BitConverter]::ToUInt32($data, 12) } else { 0 }
          $items.Add([pscustomobject]@{
            guid = $guid
            decoded = (Invoke-Rot13 $valueName)
            lastRunUtc = $lastRunUtc
            runCount = [int]$runCount
            focusCount = [int]$focusCount
            focusTime = [int64]$focusTime
          })
        }
      } catch {}
    }
  }
}
$items | ConvertTo-Json -Compress -Depth 4
"#;

const RECENT_SHORTCUTS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
$items = New-Object System.Collections.Generic.List[object]
if (Test-Path $recent) {
  $shell = New-Object -ComObject WScript.Shell
  Get-ChildItem -LiteralPath $recent -Filter *.lnk -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 600 |
    ForEach-Object {
      try {
        $shortcut = $shell.CreateShortcut($_.FullName)
        if ($shortcut.TargetPath) {
          $items.Add([pscustomobject]@{
            shortcutPath = [string]$_.FullName
            shortcutLastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
            targetPath = [string]$shortcut.TargetPath
            arguments = [string]$shortcut.Arguments
          })
        }
      } catch {}
    }
}
$items | ConvertTo-Json -Compress -Depth 4
"#;

#[derive(Debug)]
pub struct ScriptLaunchReport {
    lookback_days: i64,
    generated_at_utc: DateTime<Utc>,
    hits: Vec<ScriptLaunchHit>,
    memory_hits: Vec<MemoryResidueHit>,
    source_counts: BTreeMap<String, usize>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScriptLaunchHit {
    observed_utc: DateTime<Utc>,
    time_note: Option<String>,
    confidence: &'static str,
    source: &'static str,
    script_path: String,
    launcher: String,
    existence: &'static str,
    detail: String,
}

#[derive(Debug, Clone)]
struct MemoryResidueHit {
    process_name: String,
    pid: u32,
    process_start_utc: DateTime<Utc>,
    script_path: String,
    existence: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LauncherKind {
    Batch,
    PowerShell,
    Python,
    Node,
    ScriptHost,
    Mshta,
    Ruby,
    Perl,
    Php,
    Lua,
    Go,
    CCompiler,
    CSharpCompiler,
    JavaCompiler,
    KotlinCompiler,
    RustCompiler,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveProcessRecord {
    #[serde(default)]
    process_id: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    created_utc: String,
    #[serde(default)]
    executable_path: String,
    #[serde(default)]
    command_line: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserAssistRecord {
    #[serde(default)]
    guid: String,
    #[serde(default)]
    decoded: String,
    #[serde(default)]
    last_run_utc: String,
    #[serde(default)]
    run_count: i32,
    #[serde(default)]
    focus_count: i32,
    #[serde(default)]
    focus_time: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecentShortcutRecord {
    #[serde(default)]
    shortcut_path: String,
    #[serde(default)]
    shortcut_last_write_utc: String,
    #[serde(default)]
    target_path: String,
    #[serde(default)]
    arguments: String,
}

struct HandleGuard(HANDLE);

impl HandleGuard {
    fn open_for_read(pid: u32) -> Result<Self> {
        let access = PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0);
        let handle = unsafe { OpenProcess(access, false, pid)? };
        if handle.is_invalid() {
            anyhow::bail!("invalid handle");
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

pub fn run_script_launch_finder() -> Result<()> {
    println!("\nScript Launch Finder");
    println!("1) Last 14 days");
    println!("2) Last 30 days");
    println!("3) Back");
    print!("Select option: ");
    io::stdout().flush().ok();

    let mut choice = String::new();
    io::stdin()
        .read_line(&mut choice)
        .context("reading script finder choice")?;

    let lookback_days = match choice.trim() {
        "1" => 14,
        "2" => 30,
        "3" => return Ok(()),
        other => {
            println!("Unknown option: {other}");
            return Ok(());
        }
    };

    println!("Scanning common artifacts and live processes...");
    let report = build_report(lookback_days)?;
    print_report(&report);
    wait_for_enter();
    Ok(())
}

fn build_report(lookback_days: i64) -> Result<ScriptLaunchReport> {
    let generated_at_utc = Utc::now();
    let cutoff = generated_at_utc - Duration::days(lookback_days);
    let mut warnings = Vec::new();
    let mut hits = Vec::new();

    collect_into(
        &mut hits,
        &mut warnings,
        collect_live_process_hits(cutoff),
        "live process scan",
    );
    collect_into(
        &mut hits,
        &mut warnings,
        collect_userassist_hits(cutoff),
        "UserAssist scan",
    );
    collect_into(
        &mut hits,
        &mut warnings,
        collect_recent_shortcut_hits(cutoff),
        "Recent shortcuts scan",
    );
    collect_into(
        &mut hits,
        &mut warnings,
        collect_defender_mplog_hits(cutoff),
        "Microsoft Defender MPLog scan",
    );

    let memory_hits = match collect_memory_residue_hits() {
        Ok(items) => items,
        Err(err) => {
            warnings.push(format!("memory residue scan failed: {err}"));
            Vec::new()
        }
    };

    hits = dedup_hits(hits);
    hits.sort_by(|a, b| {
        b.observed_utc
            .cmp(&a.observed_utc)
            .then_with(|| a.script_path.cmp(&b.script_path))
    });

    let mut source_counts = BTreeMap::new();
    for hit in &hits {
        *source_counts.entry(hit.source.to_string()).or_insert(0) += 1;
    }
    if !memory_hits.is_empty() {
        source_counts.insert("Live memory residue".to_string(), memory_hits.len());
    }

    Ok(ScriptLaunchReport {
        lookback_days,
        generated_at_utc,
        hits,
        memory_hits,
        source_counts,
        warnings,
    })
}

fn collect_into<T>(
    target: &mut Vec<T>,
    warnings: &mut Vec<String>,
    result: Result<Vec<T>>,
    label: &str,
) {
    match result {
        Ok(mut items) => target.append(&mut items),
        Err(err) => warnings.push(format!("{label}: {err}")),
    }
}

fn collect_live_process_hits(cutoff: DateTime<Utc>) -> Result<Vec<ScriptLaunchHit>> {
    let records: Vec<LiveProcessRecord> = run_json_script(LIVE_PROCESS_SCRIPT)?;
    let mut hits = Vec::new();

    for record in records {
        if record.command_line.trim().is_empty() {
            continue;
        }

        let Some(observed_utc) = parse_utc(&record.created_utc) else {
            continue;
        };
        if observed_utc < cutoff {
            continue;
        }

        let launcher_name =
            preferred_launcher_name(&record.name, &record.executable_path, &record.command_line);
        let refs = extract_command_line_refs(&record.command_line, Some(&launcher_name));
        for script_path in refs {
            hits.push(ScriptLaunchHit {
                observed_utc,
                time_note: None,
                confidence: if is_absoluteish_path(&script_path) {
                    "High"
                } else {
                    "Medium"
                },
                source: "Live process command line",
                script_path: normalize_any_path(&script_path),
                launcher: format!("{launcher_name} (PID {})", record.process_id),
                existence: classify_existence(&script_path),
                detail: trim_detail(&record.command_line),
            });
        }
    }

    Ok(hits)
}

fn collect_userassist_hits(cutoff: DateTime<Utc>) -> Result<Vec<ScriptLaunchHit>> {
    let records: Vec<UserAssistRecord> = run_json_script(USERASSIST_SCRIPT)?;
    let mut hits = Vec::new();

    for record in records {
        let Some(observed_utc) = parse_utc(&record.last_run_utc) else {
            continue;
        };
        if observed_utc < cutoff {
            continue;
        }

        let paths = extract_paths_from_text(&record.decoded, false);
        if paths.is_empty() {
            continue;
        }

        let entry_type = match record.guid.to_ascii_uppercase().as_str() {
            "CEBFF5CD-ACE2-4F4F-9178-9926F41749EA" => "UserAssist executable",
            "F4E57C4B-2036-45F0-A9AB-443BCFE33D9F" => "UserAssist shortcut",
            _ => "UserAssist",
        };
        let confidence = if record.focus_time > 0 || record.focus_count > 0 {
            "Medium"
        } else {
            "Low"
        };

        for script_path in paths {
            hits.push(ScriptLaunchHit {
                observed_utc,
                time_note: Some(format!(
                    "focusTime={} focusCount={} runCount={}",
                    record.focus_time, record.focus_count, record.run_count
                )),
                confidence,
                source: "UserAssist",
                script_path: script_path.clone(),
                launcher: entry_type.to_string(),
                existence: classify_existence(&script_path),
                detail: trim_detail(&record.decoded),
            });
        }
    }

    Ok(hits)
}

fn collect_recent_shortcut_hits(cutoff: DateTime<Utc>) -> Result<Vec<ScriptLaunchHit>> {
    let records: Vec<RecentShortcutRecord> = run_json_script(RECENT_SHORTCUTS_SCRIPT)?;
    let mut hits = Vec::new();

    for record in records {
        let Some(observed_utc) = parse_utc(&record.shortcut_last_write_utc) else {
            continue;
        };
        if observed_utc < cutoff {
            continue;
        }

        let combined = if record.arguments.trim().is_empty() {
            record.target_path.clone()
        } else {
            format!("{} {}", record.target_path, record.arguments)
        };
        let launcher = preferred_launcher_name("", &record.target_path, &combined);

        let mut refs = Vec::new();
        if is_script_extension(&path_extension(&record.target_path)) {
            refs.push(normalize_any_path(&record.target_path));
        }
        refs.extend(extract_command_line_refs(&combined, Some(&launcher)));
        refs = dedup_strings(refs);

        for script_path in refs {
            hits.push(ScriptLaunchHit {
                observed_utc,
                time_note: Some("timestamp = shortcut write time".to_string()),
                confidence: "Medium",
                source: "Recent shortcut",
                script_path: script_path.clone(),
                launcher: launcher.clone(),
                existence: classify_existence(&script_path),
                detail: trim_detail(&record.shortcut_path),
            });
        }
    }

    Ok(hits)
}

fn collect_defender_mplog_hits(cutoff: DateTime<Utc>) -> Result<Vec<ScriptLaunchHit>> {
    let log_dir = std::env::var("ProgramData")
        .map(|value| Path::new(&value).join("Microsoft\\Windows Defender\\Support"))
        .unwrap_or_else(|_| {
            Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Support").to_path_buf()
        });

    if !log_dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = fs::read_dir(&log_dir)
        .with_context(|| format!("reading {}", log_dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .map(|name| name.starts_with("MPLog-"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    files.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    files.reverse();
    if files.len() > 24 {
        files.truncate(24);
    }

    let suspicious_re = Regex::new(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:\.\-]+Z)\s+Engine:command line reported as (?P<level>[A-Za-z]+): (?P<cmd>.+)$",
    )
    .unwrap();
    let perf_re = Regex::new(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:\.\-]+Z)\s+ProcessImageName: (?P<proc>[^,]+), .*? MaxTimeFile: (?P<path>.+?), EstimatedImpact:",
    )
    .unwrap();

    let mut hits = Vec::new();
    for path in files {
        let text = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(_) => String::from_utf8_lossy(&fs::read(&path).unwrap_or_default()).into_owned(),
        };

        for line in text.lines() {
            if let Some(captures) = suspicious_re.captures(line) {
                let Some(observed_utc) =
                    parse_utc(captures.name("ts").map(|m| m.as_str()).unwrap_or(""))
                else {
                    continue;
                };
                if observed_utc < cutoff {
                    continue;
                }
                let command_line = captures.name("cmd").map(|m| m.as_str()).unwrap_or("");
                let level = captures
                    .name("level")
                    .map(|m| m.as_str())
                    .unwrap_or("lowfi");
                let refs = extract_command_line_refs(command_line, None);
                for script_path in refs {
                    hits.push(ScriptLaunchHit {
                        observed_utc,
                        time_note: None,
                        confidence: if level.eq_ignore_ascii_case("threat") {
                            "High"
                        } else {
                            "Medium"
                        },
                        source: "Defender MPLog command line",
                        script_path: normalize_any_path(&script_path),
                        launcher: first_command_token(command_line)
                            .unwrap_or_else(|| "Unknown".to_string()),
                        existence: classify_existence(&script_path),
                        detail: trim_detail(command_line),
                    });
                }
                continue;
            }

            if let Some(captures) = perf_re.captures(line) {
                let Some(observed_utc) =
                    parse_utc(captures.name("ts").map(|m| m.as_str()).unwrap_or(""))
                else {
                    continue;
                };
                if observed_utc < cutoff {
                    continue;
                }
                let raw_path = captures.name("path").map(|m| m.as_str()).unwrap_or("");
                let normalized = normalize_any_path(raw_path);
                if !is_interesting_path(&normalized, false) {
                    continue;
                }
                hits.push(ScriptLaunchHit {
                    observed_utc,
                    time_note: Some("timestamp = Defender file scan event".to_string()),
                    confidence: "Low",
                    source: "Defender MPLog file scan",
                    script_path: normalized.clone(),
                    launcher: captures
                        .name("proc")
                        .map(|m| m.as_str().trim().to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    existence: classify_existence(&normalized),
                    detail: trim_detail(line),
                });
            }
        }
    }

    Ok(hits)
}

fn collect_memory_residue_hits() -> Result<Vec<MemoryResidueHit>> {
    let mut system = System::new_all();
    system.refresh_processes();

    let mut hits = Vec::new();
    let mut scanned = 0usize;

    for process in system.processes().values() {
        let name = process.name().to_string();
        if !is_memory_target_process(&name) {
            continue;
        }
        let pid = process.pid().as_u32();
        let Some(process_start_utc) = Utc.timestamp_opt(process.start_time() as i64, 0).single()
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        if scanned >= 24 {
            break;
        }
        scanned += 1;

        let process_hits = match scan_process_memory_for_paths(pid) {
            Ok(items) => items,
            Err(_) => continue,
        };

        for script_path in process_hits {
            hits.push(MemoryResidueHit {
                process_name: name.clone(),
                pid,
                process_start_utc,
                existence: classify_existence(&script_path),
                script_path,
            });
        }
    }

    hits.sort_by(|a, b| {
        b.process_start_utc
            .cmp(&a.process_start_utc)
            .then_with(|| a.script_path.cmp(&b.script_path))
    });

    let mut dedup = HashSet::new();
    hits.retain(|item| {
        dedup.insert(format!(
            "{}|{}|{}",
            item.pid,
            item.process_start_utc.timestamp(),
            item.script_path.to_ascii_lowercase()
        ))
    });

    Ok(hits)
}

fn run_json_script<T: DeserializeOwned>(script: &str) -> Result<Vec<T>> {
    let output =
        run_powershell(script).ok_or_else(|| anyhow::anyhow!("PowerShell returned no output"))?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(trimmed).context("parsing PowerShell JSON output")?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("deserializing PowerShell JSON array"),
        other => Ok(vec![
            serde_json::from_value(other).context("deserializing PowerShell JSON value")?,
        ]),
    }
}

fn parse_utc(raw: &str) -> Option<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(trimmed)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn preferred_launcher_name(name: &str, executable_path: &str, command_line: &str) -> String {
    if !name.trim().is_empty() {
        return name.trim().to_string();
    }
    if let Some(file_name) = Path::new(executable_path)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
    {
        return file_name.to_string();
    }
    first_command_token(command_line).unwrap_or_else(|| "Unknown".to_string())
}

fn extract_command_line_refs(command_line: &str, launcher_hint: Option<&str>) -> Vec<String> {
    let mut refs = extract_paths_from_text(command_line, true);
    let tokens = tokenize_command_line(command_line);
    if tokens.is_empty() {
        return dedup_strings(refs);
    }

    let launcher_name = launcher_hint
        .map(|value| value.to_string())
        .or_else(|| tokens.first().cloned())
        .unwrap_or_default();
    let launcher_kind = detect_launcher_kind(&launcher_name);

    for token in tokens.iter().skip(1) {
        let candidate = clean_candidate_token(token);
        if candidate.is_empty() || looks_like_option(&candidate) {
            continue;
        }
        if !is_interesting_for_launcher(&candidate, launcher_kind) {
            continue;
        }
        refs.push(candidate);
    }

    dedup_strings(
        refs.into_iter()
            .map(|value| normalize_any_path(&value))
            .collect(),
    )
}

fn extract_paths_from_text(text: &str, allow_source_like: bool) -> Vec<String> {
    let path_re = path_regex();
    let mut out = Vec::new();
    for capture in path_re.find_iter(text) {
        let candidate = normalize_any_path(capture.as_str());
        if is_interesting_path(&candidate, allow_source_like) {
            out.push(candidate);
        }
    }
    dedup_strings(out)
}

fn is_interesting_for_launcher(candidate: &str, launcher_kind: LauncherKind) -> bool {
    let ext = path_extension(candidate);
    if ext.is_empty() {
        return false;
    }
    let ext = ext.as_str();

    match launcher_kind {
        LauncherKind::Batch => matches!(ext, "bat" | "cmd"),
        LauncherKind::PowerShell => matches!(ext, "ps1" | "psm1" | "psd1" | "ps1xml"),
        LauncherKind::Python => matches!(ext, "py" | "pyw"),
        LauncherKind::Node => matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx"),
        LauncherKind::ScriptHost => matches!(ext, "js" | "jse" | "vbs" | "vbe" | "wsf" | "wsh"),
        LauncherKind::Mshta => matches!(ext, "hta" | "js" | "vbs"),
        LauncherKind::Ruby => ext == "rb",
        LauncherKind::Perl => ext == "pl",
        LauncherKind::Php => ext == "php",
        LauncherKind::Lua => ext == "lua",
        LauncherKind::Go => ext == "go",
        LauncherKind::CCompiler => matches!(ext, "c" | "h" | "cc" | "cpp" | "cxx"),
        LauncherKind::CSharpCompiler => ext == "cs",
        LauncherKind::JavaCompiler => ext == "java",
        LauncherKind::KotlinCompiler => matches!(ext, "kt" | "kts"),
        LauncherKind::RustCompiler => ext == "rs",
        LauncherKind::Unknown => is_script_extension(ext),
    }
}

fn is_interesting_path(path: &str, allow_source_like: bool) -> bool {
    let ext = path_extension(path);
    if ext.is_empty() {
        return false;
    }
    if is_script_extension(&ext) {
        return true;
    }
    allow_source_like && is_source_extension(&ext)
}

fn detect_launcher_kind(raw: &str) -> LauncherKind {
    let file_name = Path::new(raw)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(raw)
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase();

    match file_name.as_str() {
        "cmd.exe" | "command.com" => LauncherKind::Batch,
        "powershell.exe" | "pwsh.exe" => LauncherKind::PowerShell,
        "python.exe" | "pythonw.exe" | "py.exe" => LauncherKind::Python,
        "node.exe" => LauncherKind::Node,
        "wscript.exe" | "cscript.exe" => LauncherKind::ScriptHost,
        "mshta.exe" => LauncherKind::Mshta,
        "ruby.exe" => LauncherKind::Ruby,
        "perl.exe" => LauncherKind::Perl,
        "php.exe" => LauncherKind::Php,
        "lua.exe" => LauncherKind::Lua,
        "go.exe" => LauncherKind::Go,
        "gcc.exe" | "g++.exe" | "clang.exe" | "clang++.exe" | "cl.exe" => LauncherKind::CCompiler,
        "csc.exe" => LauncherKind::CSharpCompiler,
        "javac.exe" => LauncherKind::JavaCompiler,
        "kotlinc.exe" | "kotlinc-jvm.exe" | "kotlinc.bat" => LauncherKind::KotlinCompiler,
        "rustc.exe" => LauncherKind::RustCompiler,
        _ => LauncherKind::Unknown,
    }
}

fn tokenize_command_line(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in raw.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn first_command_token(command_line: &str) -> Option<String> {
    tokenize_command_line(command_line)
        .into_iter()
        .next()
        .map(|value| clean_candidate_token(&value))
        .filter(|value| !value.is_empty())
}

fn clean_candidate_token(raw: &str) -> String {
    let mut value = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    while value
        .chars()
        .last()
        .map(|ch| matches!(ch, ',' | ';' | ')' | ']' | '}' | '>' | '.'))
        .unwrap_or(false)
    {
        value.pop();
    }
    if let Some((_, tail)) = value.split_once('=') {
        if is_interesting_path(tail, true) {
            value = tail.to_string();
        }
    }
    value
}

fn looks_like_option(raw: &str) -> bool {
    raw.starts_with('-') || raw.starts_with("/?")
}

fn normalize_any_path(raw: &str) -> String {
    let mut value = clean_candidate_token(raw);
    if value.starts_with(r"\\?\") {
        value = value.trim_start_matches(r"\\?\").to_string();
    }
    device_path_to_dos(&value)
}

fn classify_existence(path: &str) -> &'static str {
    let normalized = normalize_any_path(path);
    if normalized.starts_with(r"\Device\") || is_unc_path(&normalized) {
        return "Unknown";
    }
    if is_absolute_drive_path(&normalized) {
        if Path::new(&normalized).exists() {
            "Present"
        } else {
            "Missing / deleted"
        }
    } else {
        "Relative / unknown"
    }
}

fn path_extension(raw: &str) -> String {
    Path::new(raw)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

fn is_script_extension(ext: &str) -> bool {
    SCRIPT_EXTS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(ext))
}

fn is_source_extension(ext: &str) -> bool {
    SOURCE_EXTS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(ext))
}

fn is_absoluteish_path(path: &str) -> bool {
    is_absolute_drive_path(path) || path.starts_with(r"\Device\") || is_unc_path(path)
}

fn is_absolute_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn is_unc_path(path: &str) -> bool {
    path.starts_with(r"\\") && !path.starts_with(r"\\?\")
}

fn dedup_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let key = value.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(value);
        }
    }
    out
}

fn dedup_hits(values: Vec<ScriptLaunchHit>) -> Vec<ScriptLaunchHit> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let key = format!(
            "{}|{}|{}|{}",
            value.source,
            value.observed_utc.timestamp(),
            value.launcher.to_ascii_lowercase(),
            value.script_path.to_ascii_lowercase()
        );
        if seen.insert(key) {
            out.push(value);
        }
    }
    out
}

fn trim_detail(raw: &str) -> String {
    let trimmed = raw.trim();
    const LIMIT: usize = 240;
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_string();
    }
    trimmed.chars().take(LIMIT).collect::<String>() + "..."
}

fn print_report(report: &ScriptLaunchReport) {
    println!();
    println!("Script Launch Finder");
    println!("Window: last {} days", report.lookback_days);
    println!("Generated: {}", format_local(report.generated_at_utc));
    println!(
        "Primary hits: {} | Memory residue: {}",
        report.hits.len(),
        report.memory_hits.len()
    );
    if !report.source_counts.is_empty() {
        println!("Sources:");
        for (source, count) in &report.source_counts {
            println!("  {}: {}", source, count);
        }
    }

    if report.hits.is_empty() {
        println!("\nNo dated script-launch evidence was found in the selected window.");
    } else {
        println!("\nRecent evidence [{}]", report.hits.len());
        println!("{}", "=".repeat(14 + digits(report.hits.len())));
        for (index, hit) in report.hits.iter().enumerate() {
            println!("{}. {}", index + 1, hit.script_path);
            println!("   ----------------------------------------");
            println!("   Time: {}", format_local(hit.observed_utc));
            if let Some(note) = &hit.time_note {
                println!("   Time Note: {}", note);
            }
            println!("   Confidence: {}", hit.confidence);
            println!("   Source: {}", hit.source);
            println!("   Launcher: {}", hit.launcher);
            println!("   Exists: {}", hit.existence);
            println!("   Detail: {}", hit.detail);
            println!();
        }
    }

    if !report.memory_hits.is_empty() {
        println!("\nLive memory residue [{}]", report.memory_hits.len());
        println!("{}", "=".repeat(22 + digits(report.memory_hits.len())));
        println!(
            "This is a supplemental live-memory section. Time shown here is the process start time; the selected 14/30-day window does not strictly apply because residue itself has no exact execution timestamp.\n"
        );
        for (index, hit) in report.memory_hits.iter().enumerate() {
            println!("{}. {}", index + 1, hit.script_path);
            println!("   ----------------------------------------");
            println!("   Process: {} (PID {})", hit.process_name, hit.pid);
            println!("   Process Start: {}", format_local(hit.process_start_utc));
            println!("   Exists: {}", hit.existence);
            println!("   Source: live memory strings");
            println!();
        }
    }

    if !report.warnings.is_empty() {
        println!("\nNotes");
        println!("=====");
        for note in &report.warnings {
            println!("- {}", note);
        }
    }
}

fn wait_for_enter() {
    println!("Press Enter to return to the menu");
    let mut buffer = String::new();
    let _ = io::stdin().read_line(&mut buffer);
}

fn format_local(value: DateTime<Utc>) -> String {
    value
        .with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn digits(value: usize) -> usize {
    value.to_string().len()
}

fn is_memory_target_process(name: &str) -> bool {
    MEMORY_PROCESS_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn scan_process_memory_for_paths(pid: u32) -> Result<Vec<String>> {
    let handle = HandleGuard::open_for_read(pid)?;
    let mut current = 0usize;
    let mut scanned_bytes = 0usize;
    let max_scanned_bytes = 20 * 1024 * 1024usize;
    let mut hits = HashSet::new();

    while scanned_bytes < max_scanned_bytes {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQueryEx(
                handle.raw(),
                Some(current as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if result == 0 {
            break;
        }

        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;
        if region_size == 0 {
            break;
        }

        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let mut offset = region_base;
            while offset < region_base.saturating_add(region_size)
                && scanned_bytes < max_scanned_bytes
            {
                let remaining = region_base
                    .saturating_add(region_size)
                    .saturating_sub(offset);
                let chunk_size = remaining.min(256 * 1024);
                if let Ok(bytes) = read_process_bytes(handle.raw(), offset, chunk_size) {
                    scanned_bytes = scanned_bytes.saturating_add(bytes.len());
                    for item in extract_paths_from_memory_chunk(&bytes) {
                        hits.insert(normalize_any_path(&item));
                        if hits.len() >= 40 {
                            return Ok(hits.into_iter().collect());
                        }
                    }
                }
                offset = offset.saturating_add(chunk_size.max(1));
            }
        }

        current = region_base.saturating_add(region_size);
        if current == 0 {
            break;
        }
    }

    Ok(hits.into_iter().collect())
}

fn read_process_bytes(handle: HANDLE, address: usize, len: usize) -> Result<Vec<u8>> {
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

fn extract_paths_from_memory_chunk(bytes: &[u8]) -> Vec<String> {
    let mut ascii = String::with_capacity(bytes.len());
    for byte in bytes {
        if is_printable_ascii(*byte) {
            ascii.push(*byte as char);
        } else {
            ascii.push('\n');
        }
    }

    let mut wide = String::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        if pair[1] == 0 && is_printable_ascii(pair[0]) {
            wide.push(pair[0] as char);
        } else {
            wide.push('\n');
        }
    }

    let mut paths = extract_paths_from_text(&ascii, true);
    paths.extend(extract_paths_from_text(&wide, true));
    dedup_strings(paths)
}

fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, b' '..=b'~')
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

fn path_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:[A-Z]:\\|\\\\\?\\[A-Z]:\\|\\\\[^\\/\r\n]+\\[^\\/\r\n]+\\|\\Device\\HarddiskVolume\d+\\)[^"<>|\r\n]{1,280}\.(?:bat|cmd|ps1|psm1|psd1|ps1xml|py|pyw|js|jse|vbs|vbe|wsf|wsh|hta|ahk|lua|rb|pl|php|mjs|cjs|c|h|cc|cpp|cxx|cs|java|go|rs|kt|kts|ts|tsx|jsx)\b"#,
        )
        .expect("valid path regex")
    })
}

fn device_path_to_dos(raw: &str) -> String {
    for (device_prefix, drive_prefix) in device_prefix_map() {
        if raw
            .to_ascii_lowercase()
            .starts_with(&device_prefix.to_ascii_lowercase())
        {
            return format!("{}{}", drive_prefix, &raw[device_prefix.len()..]);
        }
    }
    raw.to_string()
}

fn device_prefix_map() -> &'static Vec<(String, String)> {
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut items = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let mut wide: Vec<u16> = OsStr::new(&drive).encode_wide().collect();
            wide.push(0);
            let mut buffer = vec![0u16; 1024];
            let len = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut buffer)) };
            if len == 0 {
                continue;
            }
            let value = String::from_utf16_lossy(&buffer[..len as usize]);
            if let Some(first) = value.split('\0').find(|item| !item.is_empty()) {
                items.push((first.to_string(), format!("{}\\", drive)));
            }
        }
        items.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        items
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quoted_paths() {
        let tokens = tokenize_command_line(r#"python.exe "C:\Users\me\test file.py" --flag"#);
        assert_eq!(tokens[0], "python.exe");
        assert_eq!(tokens[1], r#"C:\Users\me\test file.py"#);
    }

    #[test]
    fn extracts_relative_python_script_from_command_line() {
        let refs = extract_command_line_refs(r#"python 123.py"#, Some("python.exe"));
        assert!(refs.iter().any(|item| item.eq_ignore_ascii_case("123.py")));
    }

    #[test]
    fn recognizes_device_path_as_interesting() {
        let paths =
            extract_paths_from_text(r#"\Device\HarddiskVolume3\Users\me\Desktop\run.bat"#, true);
        assert_eq!(paths.len(), 1);
    }
}
