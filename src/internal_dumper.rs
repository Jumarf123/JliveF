use crate::dump_report;
use anyhow::{Context, Result, anyhow};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString, c_void};
use std::fs;
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    WaitForSingleObject,
};
use windows::core::{PCSTR, PCWSTR, s};

const AGENT_DIR: &str = "agents";
const PROTOCOL_VERSION: u32 = 4;
const SESSION_TEXT_CAP: usize = 1024;
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(300);
const CORE_TIMEOUT: Duration = Duration::from_secs(45);
const EXTENDED_TIMEOUT: Duration = Duration::from_secs(30);
const EXTENDED_NATIVE_TIMEOUT: Duration = Duration::from_secs(20);
const REMOTE_THREAD_TIMEOUT_MS: u32 = 10_000;
const CORE_BATCH_SIZE: u32 = 128;
const EXTENDED_BATCH_SIZE: u32 = 64;
const EXTENDED_NATIVE_BATCH_SIZE: u32 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AgentFlavor {
    LegacyJvmti,
    ModernJvmti,
}

impl AgentFlavor {
    fn label(self) -> &'static str {
        match self {
            Self::LegacyJvmti => "legacy_jvmti",
            Self::ModernJvmti => "modern_jvmti",
        }
    }

    fn id(self) -> u32 {
        match self {
            Self::LegacyJvmti => 1,
            Self::ModernJvmti => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TargetArch {
    X86,
    X64,
}

impl TargetArch {
    fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DumpProfile {
    Core,
    Extended,
}

impl DumpProfile {
    fn label(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Extended => "extended",
        }
    }

    fn id(self) -> u32 {
        match self {
            Self::Core => 1,
            Self::Extended => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransportMode {
    RuntimeAttach,
    ExternalAttach,
    NativeFallback,
}

impl TransportMode {
    fn label(self) -> &'static str {
        match self {
            Self::RuntimeAttach => "runtime_attach",
            Self::ExternalAttach => "external_attach",
            Self::NativeFallback => "native_fallback",
        }
    }

    fn id(self) -> u32 {
        match self {
            Self::RuntimeAttach => 1,
            Self::ExternalAttach => 2,
            Self::NativeFallback => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeKind {
    System,
    Bundled,
    Custom,
}

impl RuntimeKind {
    fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Bundled => "bundled",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone)]
struct AttachCapabilities {
    native_injection: bool,
    runtime_jcmd_available: bool,
    external_jcmd_available: bool,
}

#[derive(Debug, Clone)]
struct DetectedRuntime {
    java_major: u32,
    arch: TargetArch,
    vendor_hint: String,
    jvm_path: PathBuf,
    runtime_home: PathBuf,
    agent_flavor: AgentFlavor,
    attach_capabilities: AttachCapabilities,
    runtime_kind: RuntimeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AttachStrategy {
    RuntimeJcmd,
    ExternalJcmd,
    NativeCreateRemoteThread,
    NativeNtCreateThreadEx,
}

impl AttachStrategy {
    fn label(self) -> &'static str {
        match self {
            Self::RuntimeJcmd => "runtime_jcmd",
            Self::ExternalJcmd => "external_jcmd",
            Self::NativeCreateRemoteThread => "native_loadlibrary",
            Self::NativeNtCreateThreadEx => "native_ntcreatethreadex",
        }
    }

    fn transport_mode(self) -> TransportMode {
        match self {
            Self::RuntimeJcmd => TransportMode::RuntimeAttach,
            Self::ExternalJcmd => TransportMode::ExternalAttach,
            Self::NativeCreateRemoteThread | Self::NativeNtCreateThreadEx => {
                TransportMode::NativeFallback
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct JavaProcessEntry {
    index: usize,
    name: String,
    pid: u32,
    working_set_bytes: u64,
    working_set_gb: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RemoteDumpSessionConfig {
    protocol_version: u32,
    target_pid: u32,
    detected_java_major: u32,
    agent_flavor: u32,
    dump_profile: u32,
    transport_mode: u32,
    batch_size: u32,
    close_after_success: u32,
    session_id: [u16; SESSION_TEXT_CAP],
    profile_output_dir: [u16; SESSION_TEXT_CAP],
    rawdump_tmp_path: [u16; SESSION_TEXT_CAP],
    rawdump_final_path: [u16; SESSION_TEXT_CAP],
    status_json_path: [u16; SESSION_TEXT_CAP],
    agent_log_path: [u16; SESSION_TEXT_CAP],
}

#[derive(Debug, Clone)]
struct ProfileArtifacts {
    profile: DumpProfile,
    output_dir: PathBuf,
    config_path: PathBuf,
    rawdump_tmp_path: PathBuf,
    rawdump_final_path: PathBuf,
    status_json_path: PathBuf,
    agent_log_path: PathBuf,
}

#[derive(Debug, Clone)]
struct DumpSession {
    session_id: String,
    session_dir: PathBuf,
    transport_dir: PathBuf,
    staged_agent_path: PathBuf,
    manifest_path: PathBuf,
    core: ProfileArtifacts,
    extended: ProfileArtifacts,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct DumpSessionStatus {
    pub session_id: Option<String>,
    pub phase: Option<String>,
    pub message: Option<String>,
    pub target_pid: Option<u32>,
    pub detected_java_major: Option<u32>,
    pub agent_flavor: Option<String>,
    pub dump_profile: Option<String>,
    pub transport_mode: Option<String>,
    pub dump_completion: Option<String>,
    pub last_error_code: Option<u32>,
    pub classes_enumerated: Option<u32>,
    pub classes_dumped: Option<u32>,
    pub classes_skipped_signature: Option<u32>,
    pub classes_skipped_metadata: Option<u32>,
    pub classes_skipped_provenance: Option<u32>,
    pub classes_skipped_jni: Option<u32>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ProfileRunResult {
    strategy: AttachStrategy,
    transport_mode: TransportMode,
    status: DumpSessionStatus,
    inspection: dump_report::DumpInspection,
    processed: dump_report::ProcessedDump,
    result_label: String,
}

#[derive(Debug, Serialize)]
struct SessionManifest {
    session_id: String,
    target_pid: u32,
    target_name: String,
    target_working_set_gb: f64,
    session_dir: String,
    runtime: SessionRuntime,
    core: SessionProfileSummary,
    extended: SessionProfileSummary,
}

#[derive(Debug, Serialize)]
struct SessionRuntime {
    java_major: u32,
    arch: String,
    vendor_hint: String,
    runtime_kind: String,
    jvm_path: String,
    runtime_home: String,
    attach_api_available: bool,
    jcmd_runtime_available: bool,
    jcmd_external_available: bool,
    native_attach_possible: bool,
    profile_order: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SessionProfileSummary {
    profile: String,
    result: String,
    attach_strategy: Option<String>,
    transport_mode: Option<String>,
    status_path: String,
    log_path: String,
    rawdump_path: Option<String>,
    report_path: Option<String>,
    html_path: Option<String>,
    classes_enumerated: Option<usize>,
    classes_dumped: Option<usize>,
    classes_skipped: Option<usize>,
    message: Option<String>,
}

pub fn run_dumper() -> Result<()> {
    let processes = list_java_processes()?;
    if processes.is_empty() {
        return Err(anyhow!("No running javaw.exe processes were found"));
    }

    println!("Available javaw.exe processes:");
    for process in &processes {
        println!(
            "{}) {} {:.1} GB - {}",
            process.index, process.name, process.working_set_gb, process.pid
        );
    }
    print!("Select process index or PID: ");
    io::stdout().flush().ok();

    let mut selection = String::new();
    io::stdin()
        .read_line(&mut selection)
        .context("reading process selection")?;
    let target = resolve_process_selection(selection.trim(), &processes)?;

    let runtime = detect_runtime(target.pid).context("detecting target runtime")?;
    let session = DumpSession::create(target.pid)?;
    let agent_path = session.stage_agent(&locate_agent(&runtime)?)?;
    let attach_order = attach_strategy_order(&runtime);

    println!("Target PID: {}", target.pid);
    println!(
        "Detected runtime: Java {} [{}] via {}",
        runtime.java_major,
        runtime.arch.label(),
        runtime.jvm_path.display()
    );
    println!(
        "Runtime kind: {} | vendor hint: {}",
        runtime.runtime_kind.label(),
        runtime.vendor_hint
    );
    println!("Agent flavor: {}", runtime.agent_flavor.label());
    println!(
        "Attach order: {}",
        attach_order
            .iter()
            .map(|item| item.label())
            .collect::<Vec<_>>()
            .join(" -> ")
    );
    println!("Results: {}", session.session_dir.display());
    println!("Transport: {}", session.transport_dir.display());
    println!("Using agent: {}", agent_path.display());

    let core = match run_profile(
        target.pid,
        &runtime,
        &session.session_id,
        &session.core,
        &agent_path,
        None,
    ) {
        Ok(result) => {
            println!("Core dump: {}", result.processed.report_path.display());
            println!("Core HTML: {}", result.processed.html_path.display());
            println!(
                "Core classes: dumped={} enumerated={} skipped={}",
                result.inspection.classes_dumped,
                result
                    .inspection
                    .classes_enumerated
                    .unwrap_or(result.inspection.classes_dumped),
                result.inspection.classes_skipped.unwrap_or(0)
            );
            result
        }
        Err(err) => {
            let manifest = build_manifest(
                &session,
                &target,
                &runtime,
                SessionProfileSummary {
                    profile: DumpProfile::Core.label().to_string(),
                    result: "error".to_string(),
                    attach_strategy: None,
                    transport_mode: None,
                    status_path: session.core.status_json_path.display().to_string(),
                    log_path: session.core.agent_log_path.display().to_string(),
                    rawdump_path: None,
                    report_path: None,
                    html_path: None,
                    classes_enumerated: None,
                    classes_dumped: None,
                    classes_skipped: None,
                    message: Some(err.to_string()),
                },
                SessionProfileSummary {
                    profile: DumpProfile::Extended.label().to_string(),
                    result: "skipped".to_string(),
                    attach_strategy: None,
                    transport_mode: None,
                    status_path: session.extended.status_json_path.display().to_string(),
                    log_path: session.extended.agent_log_path.display().to_string(),
                    rawdump_path: None,
                    report_path: None,
                    html_path: None,
                    classes_enumerated: None,
                    classes_dumped: None,
                    classes_skipped: None,
                    message: Some("core phase failed".to_string()),
                },
            );
            write_manifest(&session.manifest_path, &manifest)?;
            return Err(err);
        }
    };

    let extended = match run_profile(
        target.pid,
        &runtime,
        &session.session_id,
        &session.extended,
        &agent_path,
        Some(core.strategy),
    ) {
        Ok(result) => {
            println!("Extended dump: {}", result.processed.report_path.display());
            println!("Extended HTML: {}", result.processed.html_path.display());
            println!(
                "Extended classes: dumped={} enumerated={} skipped={} result={}",
                result.inspection.classes_dumped,
                result
                    .inspection
                    .classes_enumerated
                    .unwrap_or(result.inspection.classes_dumped),
                result.inspection.classes_skipped.unwrap_or(0),
                result.result_label
            );
            summary_from_result(DumpProfile::Extended, &session.extended, &result)
        }
        Err(err) => {
            println!("Extended phase did not complete cleanly: {err}");
            SessionProfileSummary {
                profile: DumpProfile::Extended.label().to_string(),
                result: "error".to_string(),
                attach_strategy: Some(core.strategy.label().to_string()),
                transport_mode: Some(core.transport_mode.label().to_string()),
                status_path: session.extended.status_json_path.display().to_string(),
                log_path: session.extended.agent_log_path.display().to_string(),
                rawdump_path: session
                    .extended
                    .rawdump_final_path
                    .exists()
                    .then(|| session.extended.rawdump_final_path.display().to_string()),
                report_path: None,
                html_path: None,
                classes_enumerated: None,
                classes_dumped: None,
                classes_skipped: None,
                message: Some(err.to_string()),
            }
        }
    };

    let manifest = build_manifest(
        &session,
        &target,
        &runtime,
        summary_from_result(DumpProfile::Core, &session.core, &core),
        extended,
    );
    write_manifest(&session.manifest_path, &manifest)?;
    println!("Session manifest: {}", session.manifest_path.display());
    println!("Minecraft process was left running.");
    Ok(())
}

impl DumpSession {
    fn create(pid: u32) -> Result<Self> {
        let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
        let session_id = Uuid::new_v4().simple().to_string();
        let exe = std::env::current_exe().context("getting current exe path")?;
        let exe_dir = exe
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("Cannot resolve executable directory"))?;
        let preferred_session_dir = exe_dir
            .join("results")
            .join("internal_dumper")
            .join(format!("{timestamp}-{pid}-{session_id}"));
        let session_dir = match fs::create_dir_all(&preferred_session_dir) {
            Ok(()) => preferred_session_dir,
            Err(_) => {
                let fallback = std::env::temp_dir()
                    .join("jlivef")
                    .join("internal_dumper")
                    .join(format!("{timestamp}-{pid}-{session_id}"));
                fs::create_dir_all(&fallback)
                    .with_context(|| format!("creating session dir {}", fallback.display()))?;
                fallback
            }
        };

        let transport_dir = session_dir.join("_transport");
        let config_dir = std::env::temp_dir()
            .join("jlivef")
            .join("internal_dumper_attach")
            .join(&session_id);
        let core_dir = session_dir.join(DumpProfile::Core.label());
        let extended_dir = session_dir.join(DumpProfile::Extended.label());
        fs::create_dir_all(&transport_dir)
            .with_context(|| format!("creating {}", transport_dir.display()))?;
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("creating {}", config_dir.display()))?;
        fs::create_dir_all(&core_dir)
            .with_context(|| format!("creating {}", core_dir.display()))?;
        fs::create_dir_all(&extended_dir)
            .with_context(|| format!("creating {}", extended_dir.display()))?;

        Ok(Self {
            session_id,
            staged_agent_path: transport_dir.join("JVMTI_Agent.dll"),
            manifest_path: session_dir.join("session.json"),
            core: ProfileArtifacts::new(DumpProfile::Core, &core_dir, &config_dir),
            extended: ProfileArtifacts::new(DumpProfile::Extended, &extended_dir, &config_dir),
            session_dir,
            transport_dir,
        })
    }

    fn stage_agent(&self, source: &Path) -> Result<PathBuf> {
        fs::copy(source, &self.staged_agent_path).with_context(|| {
            format!(
                "copying agent from {} to {}",
                source.display(),
                self.staged_agent_path.display()
            )
        })?;
        Ok(self.staged_agent_path.clone())
    }
}

impl ProfileArtifacts {
    fn new(profile: DumpProfile, output_dir: &Path, config_dir: &Path) -> Self {
        Self {
            profile,
            output_dir: output_dir.to_path_buf(),
            config_path: config_dir.join(format!("{}.session.cfg", profile.label())),
            rawdump_tmp_path: output_dir.join("classes.rawdump.tmp"),
            rawdump_final_path: output_dir.join("classes.rawdump"),
            status_json_path: output_dir.join("status.json"),
            agent_log_path: output_dir.join("agent.log"),
        }
    }

    fn timeout(&self, strategy: AttachStrategy) -> Duration {
        match (self.profile, strategy.transport_mode()) {
            (DumpProfile::Core, _) => CORE_TIMEOUT,
            (DumpProfile::Extended, TransportMode::NativeFallback) => EXTENDED_NATIVE_TIMEOUT,
            (DumpProfile::Extended, _) => EXTENDED_TIMEOUT,
        }
    }

    fn write_config(
        &self,
        pid: u32,
        runtime: &DetectedRuntime,
        session_id: &str,
        transport_mode: TransportMode,
    ) -> Result<()> {
        let contents = [
            format!("protocol_version={PROTOCOL_VERSION}"),
            format!("target_pid={pid}"),
            format!("detected_java_major={}", runtime.java_major),
            format!("agent_flavor={}", runtime.agent_flavor.label()),
            format!("dump_profile={}", self.profile.label()),
            format!("transport_mode={}", transport_mode.label()),
            format!("batch_size={}", self.batch_size_from_transport(transport_mode)),
            "close_after_success=0".to_string(),
            "resume_allowed=0".to_string(),
            format!("session_id={session_id}"),
            format!("profile_output_dir={}", self.output_dir.display()),
            format!("rawdump_tmp_path={}", self.rawdump_tmp_path.display()),
            format!("rawdump_final_path={}", self.rawdump_final_path.display()),
            format!("status_json_path={}", self.status_json_path.display()),
            format!("agent_log_path={}", self.agent_log_path.display()),
        ]
        .join("\n");
        fs::write(&self.config_path, contents)
            .with_context(|| format!("writing session config {}", self.config_path.display()))
    }

    fn to_remote_config(
        &self,
        session_id: &str,
        runtime: &DetectedRuntime,
        pid: u32,
        transport_mode: TransportMode,
    ) -> RemoteDumpSessionConfig {
        let mut config = RemoteDumpSessionConfig {
            protocol_version: PROTOCOL_VERSION,
            target_pid: pid,
            detected_java_major: runtime.java_major,
            agent_flavor: runtime.agent_flavor.id(),
            dump_profile: self.profile.id(),
            transport_mode: transport_mode.id(),
            batch_size: self.batch_size_from_transport(transport_mode),
            close_after_success: 0,
            session_id: [0; SESSION_TEXT_CAP],
            profile_output_dir: [0; SESSION_TEXT_CAP],
            rawdump_tmp_path: [0; SESSION_TEXT_CAP],
            rawdump_final_path: [0; SESSION_TEXT_CAP],
            status_json_path: [0; SESSION_TEXT_CAP],
            agent_log_path: [0; SESSION_TEXT_CAP],
        };
        copy_wide_into(&mut config.session_id, session_id);
        copy_wide_into(&mut config.profile_output_dir, &self.output_dir);
        copy_wide_into(&mut config.rawdump_tmp_path, &self.rawdump_tmp_path);
        copy_wide_into(&mut config.rawdump_final_path, &self.rawdump_final_path);
        copy_wide_into(&mut config.status_json_path, &self.status_json_path);
        copy_wide_into(&mut config.agent_log_path, &self.agent_log_path);
        config
    }

    fn batch_size_from_transport(&self, transport_mode: TransportMode) -> u32 {
        match (self.profile, transport_mode) {
            (DumpProfile::Core, _) => CORE_BATCH_SIZE,
            (DumpProfile::Extended, TransportMode::NativeFallback) => EXTENDED_NATIVE_BATCH_SIZE,
            (DumpProfile::Extended, _) => EXTENDED_BATCH_SIZE,
        }
    }
}

fn list_java_processes() -> Result<Vec<JavaProcessEntry>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    if snapshot.is_invalid() {
        return Err(anyhow!("Unable to create process snapshot"));
    }

    let mut processes = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        let exe_name = utf16_buf_to_string(&entry.szExeFile);
        if exe_name.eq_ignore_ascii_case("javaw.exe") {
            let memory_bytes = process_working_set(entry.th32ProcessID).unwrap_or(0);
            processes.push(JavaProcessEntry {
                index: 0,
                name: exe_name,
                pid: entry.th32ProcessID,
                working_set_bytes: memory_bytes,
                working_set_gb: bytes_to_gb(memory_bytes),
            });
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    processes.sort_by(|left, right| {
        right
            .working_set_bytes
            .cmp(&left.working_set_bytes)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    for (index, process) in processes.iter_mut().enumerate() {
        process.index = index + 1;
    }
    Ok(processes)
}

fn process_working_set(pid: u32) -> Result<u64> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
    if process.is_invalid() {
        return Err(anyhow!("OpenProcess failed for pid {pid}"));
    }

    let mut counters: PROCESS_MEMORY_COUNTERS_EX = unsafe { zeroed() };
    let ok = unsafe {
        K32GetProcessMemoryInfo(
            process,
            &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut _,
            size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    };
    unsafe {
        let _ = CloseHandle(process);
    }
    if ok.as_bool() {
        Ok(counters.WorkingSetSize as u64)
    } else {
        Err(anyhow!("GetProcessMemoryInfo failed for pid {pid}"))
    }
}

fn resolve_process_selection(
    raw: &str,
    processes: &[JavaProcessEntry],
) -> Result<JavaProcessEntry> {
    let parsed = raw
        .trim()
        .parse::<u32>()
        .map_err(|_| anyhow!("Invalid process selection: {raw}"))?;
    if let Some(process) = processes.iter().find(|process| process.pid == parsed) {
        return Ok(process.clone());
    }
    let index = parsed as usize;
    processes
        .iter()
        .find(|process| process.index == index)
        .cloned()
        .ok_or_else(|| anyhow!("No javaw.exe matches index or PID {raw}"))
}

fn detect_runtime(pid: u32) -> Result<DetectedRuntime> {
    let jvm_path = find_jvm_module(pid)?;
    let runtime_home = runtime_home_from_jvm(&jvm_path)?;
    let java_major = detect_java_major(&jvm_path, &runtime_home)?;
    let arch = detect_target_arch(&jvm_path);
    let vendor_hint = runtime_home
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("unknown")
        .to_string();
    let runtime_jcmd_available = find_runtime_jcmd(&runtime_home).is_some();
    let external_jcmd_available = find_external_jcmd(&runtime_home).is_some();

    Ok(DetectedRuntime {
        java_major,
        arch,
        vendor_hint,
        jvm_path,
        runtime_home: runtime_home.clone(),
        agent_flavor: if java_major <= 8 {
            AgentFlavor::LegacyJvmti
        } else {
            AgentFlavor::ModernJvmti
        },
        attach_capabilities: AttachCapabilities {
            native_injection: current_arch() == arch,
            runtime_jcmd_available,
            external_jcmd_available,
        },
        runtime_kind: classify_runtime_kind(&runtime_home),
    })
}

fn classify_runtime_kind(runtime_home: &Path) -> RuntimeKind {
    let lower = runtime_home.to_string_lossy().to_ascii_lowercase();
    if lower.contains(r"\program files\java")
        || lower.contains(r"\program files\eclipse adoptium")
        || lower.contains(r"\program files\microsoft")
    {
        RuntimeKind::System
    } else if lower.contains(".minecraft")
        || lower.contains(".tlauncher")
        || lower.contains("lunar")
        || lower.contains("roaming")
    {
        RuntimeKind::Bundled
    } else {
        RuntimeKind::Custom
    }
}

fn attach_strategy_order(runtime: &DetectedRuntime) -> Vec<AttachStrategy> {
    let mut strategies = Vec::new();
    if runtime.attach_capabilities.runtime_jcmd_available {
        strategies.push(AttachStrategy::RuntimeJcmd);
    }
    if runtime.attach_capabilities.external_jcmd_available {
        strategies.push(AttachStrategy::ExternalJcmd);
    }
    if runtime.attach_capabilities.native_injection {
        strategies.push(AttachStrategy::NativeCreateRemoteThread);
        strategies.push(AttachStrategy::NativeNtCreateThreadEx);
    }
    strategies
}

fn run_profile(
    pid: u32,
    runtime: &DetectedRuntime,
    session_id: &str,
    artifacts: &ProfileArtifacts,
    agent_path: &Path,
    forced_strategy: Option<AttachStrategy>,
) -> Result<ProfileRunResult> {
    let strategies = forced_strategy
        .map(|strategy| vec![strategy])
        .unwrap_or_else(|| attach_strategy_order(runtime));
    let mut failures = Vec::new();

    for strategy in strategies {
        let transport_mode = strategy.transport_mode();
        artifacts.write_config(pid, runtime, session_id, transport_mode)?;
        clear_profile_artifacts(artifacts)?;
        println!(
            "Starting {} phase with {}",
            artifacts.profile.label(),
            strategy.label()
        );
        match start_dump_session(pid, runtime, session_id, artifacts, agent_path, strategy) {
            Ok(()) => {
                let wait_result = wait_for_session(artifacts, artifacts.timeout(strategy));
                let status = match wait_result {
                    Ok(status) => status,
                    Err(err) => {
                        if artifacts.rawdump_final_path.exists() {
                            read_status(&artifacts.status_json_path)?.unwrap_or_else(|| {
                                DumpSessionStatus {
                                    phase: Some("partial_success".to_string()),
                                    message: Some(err.to_string()),
                                    ..DumpSessionStatus::default()
                                }
                            })
                        } else {
                            failures.push(format!("{}: {err}", strategy.label()));
                            continue;
                        }
                    }
                };
                let inspection =
                    dump_report::inspect_dump_file(&artifacts.rawdump_final_path).with_context(
                        || format!("validating {}", artifacts.rawdump_final_path.display()),
                    )?;
                let processed = process_dump_file_with_retry(
                    &artifacts.rawdump_final_path,
                    Duration::from_secs(15),
                )?;
                let result_label = match status.phase.as_deref() {
                    Some("partial_success") => "partial_success".to_string(),
                    Some("success") => "success".to_string(),
                    _ if artifacts.profile == DumpProfile::Extended
                        && inspection.classes_skipped.unwrap_or(0) > 0 =>
                    {
                        "partial_success".to_string()
                    }
                    _ => "success".to_string(),
                };
                return Ok(ProfileRunResult {
                    strategy,
                    transport_mode,
                    status,
                    inspection,
                    processed,
                    result_label,
                });
            }
            Err(err) => failures.push(format!("{}: {err}", strategy.label())),
        }
    }

    Err(anyhow!(
        "{} phase failed: {}",
        artifacts.profile.label(),
        failures.join(" | ")
    ))
}

fn clear_profile_artifacts(artifacts: &ProfileArtifacts) -> Result<()> {
    for path in [
        &artifacts.rawdump_tmp_path,
        &artifacts.rawdump_final_path,
        &artifacts.status_json_path,
        &artifacts.agent_log_path,
    ] {
        if path.exists() {
            fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
        }
    }
    Ok(())
}

fn build_manifest(
    session: &DumpSession,
    target: &JavaProcessEntry,
    runtime: &DetectedRuntime,
    core: SessionProfileSummary,
    extended: SessionProfileSummary,
) -> SessionManifest {
    SessionManifest {
        session_id: session.session_id.clone(),
        target_pid: target.pid,
        target_name: target.name.clone(),
        target_working_set_gb: target.working_set_gb,
        session_dir: session.session_dir.display().to_string(),
        runtime: SessionRuntime {
            java_major: runtime.java_major,
            arch: runtime.arch.label().to_string(),
            vendor_hint: runtime.vendor_hint.clone(),
            runtime_kind: runtime.runtime_kind.label().to_string(),
            jvm_path: runtime.jvm_path.display().to_string(),
            runtime_home: runtime.runtime_home.display().to_string(),
            attach_api_available: true,
            jcmd_runtime_available: runtime.attach_capabilities.runtime_jcmd_available,
            jcmd_external_available: runtime.attach_capabilities.external_jcmd_available,
            native_attach_possible: runtime.attach_capabilities.native_injection,
            profile_order: vec![
                DumpProfile::Core.label().to_string(),
                DumpProfile::Extended.label().to_string(),
            ],
        },
        core,
        extended,
    }
}

fn summary_from_result(
    profile: DumpProfile,
    artifacts: &ProfileArtifacts,
    result: &ProfileRunResult,
) -> SessionProfileSummary {
    SessionProfileSummary {
        profile: profile.label().to_string(),
        result: result.result_label.clone(),
        attach_strategy: Some(result.strategy.label().to_string()),
        transport_mode: Some(result.transport_mode.label().to_string()),
        status_path: artifacts.status_json_path.display().to_string(),
        log_path: artifacts.agent_log_path.display().to_string(),
        rawdump_path: Some(artifacts.rawdump_final_path.display().to_string()),
        report_path: Some(result.processed.report_path.display().to_string()),
        html_path: Some(result.processed.html_path.display().to_string()),
        classes_enumerated: result.inspection.classes_enumerated,
        classes_dumped: Some(result.inspection.classes_dumped),
        classes_skipped: result.inspection.classes_skipped,
        message: result.status.message.clone(),
    }
}

fn write_manifest(path: &Path, manifest: &SessionManifest) -> Result<()> {
    let payload = serde_json::to_string_pretty(manifest)?;
    fs::write(path, payload).with_context(|| format!("writing {}", path.display()))
}

fn locate_agent(runtime: &DetectedRuntime) -> Result<PathBuf> {
    let flavor_dirs: &[&str] = match runtime.agent_flavor {
        AgentFlavor::LegacyJvmti => &["java8"],
        AgentFlavor::ModernJvmti => &["modern", "java21", "java17"],
    };
    let arch_dirs: &[&str] = match runtime.arch {
        TargetArch::X64 => &["x64", "amd64"],
        TargetArch::X86 => &["x86", "win32"],
    };

    let exe = std::env::current_exe().context("getting current exe path")?;
    let exe_dir = exe
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Cannot resolve executable directory"))?;

    let mut roots = vec![exe_dir.clone()];
    if let Some(parent) = exe_dir.parent() {
        roots.push(parent.to_path_buf());
        if let Some(grand) = parent.parent() {
            roots.push(grand.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }

    let mut tried = Vec::new();
    for root in roots {
        for flavor in flavor_dirs {
            let layouts = [
                root.join(AGENT_DIR).join(flavor).join("JVMTI_Agent.dll"),
                root.join(AGENT_DIR)
                    .join("1")
                    .join(flavor)
                    .join("JVMTI_Agent.dll"),
                root.join(flavor).join("JVMTI_Agent.dll"),
            ];
            for candidate in layouts {
                tried.push(candidate.display().to_string());
                if candidate.exists() {
                    return Ok(candidate);
                }
            }

            for arch_dir in arch_dirs {
                let layouts = [
                    root.join(AGENT_DIR)
                        .join(arch_dir)
                        .join(flavor)
                        .join("JVMTI_Agent.dll"),
                    root.join(AGENT_DIR)
                        .join(flavor)
                        .join(arch_dir)
                        .join("JVMTI_Agent.dll"),
                ];
                for candidate in layouts {
                    tried.push(candidate.display().to_string());
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "Agent not found for {} {}. Tried: {}",
        runtime.agent_flavor.label(),
        runtime.arch.label(),
        tried.join(" | ")
    ))
}

fn start_dump_session(
    pid: u32,
    runtime: &DetectedRuntime,
    session_id: &str,
    artifacts: &ProfileArtifacts,
    agent_path: &Path,
    strategy: AttachStrategy,
) -> Result<()> {
    match strategy {
        AttachStrategy::RuntimeJcmd => {
            let jcmd = find_runtime_jcmd(&runtime.runtime_home)
                .ok_or_else(|| anyhow!("runtime jcmd.exe not found"))?;
            attach_with_jcmd(pid, artifacts, agent_path, &jcmd)
        }
        AttachStrategy::ExternalJcmd => {
            let jcmd = find_external_jcmd(&runtime.runtime_home)
                .ok_or_else(|| anyhow!("external jcmd.exe not found"))?;
            attach_with_jcmd(pid, artifacts, agent_path, &jcmd)
        }
        AttachStrategy::NativeCreateRemoteThread => inject_agent_native(
            pid,
            runtime,
            session_id,
            artifacts,
            agent_path,
            RemoteThreadKind::CreateRemoteThread,
            TransportMode::NativeFallback,
        ),
        AttachStrategy::NativeNtCreateThreadEx => inject_agent_native(
            pid,
            runtime,
            session_id,
            artifacts,
            agent_path,
            RemoteThreadKind::NtCreateThreadEx,
            TransportMode::NativeFallback,
        ),
    }
}

fn wait_for_session(artifacts: &ProfileArtifacts, timeout: Duration) -> Result<DumpSessionStatus> {
    let start = Instant::now();
    let mut last_status = DumpSessionStatus::default();
    while start.elapsed() < timeout {
        if let Some(status) = read_status(&artifacts.status_json_path)? {
            last_status = status;
            match last_status.phase.as_deref() {
                Some("error") => {
                    if artifacts.rawdump_final_path.exists() {
                        return Ok(last_status);
                    }
                    let message = last_status
                        .message
                        .clone()
                        .unwrap_or_else(|| "agent reported failure".to_string());
                    return Err(anyhow!("{message}"));
                }
                Some("success") | Some("partial_success") => {
                    if artifacts.rawdump_final_path.exists() {
                        return Ok(last_status);
                    }
                }
                _ => {}
            }
        }
        if artifacts.rawdump_final_path.exists() {
            return Ok(last_status);
        }
        thread::sleep(STATUS_POLL_INTERVAL);
    }

    if artifacts.rawdump_final_path.exists() {
        return Ok(last_status);
    }

    let mut message = format!(
        "Timed out waiting for {} phase. Status file: {}",
        artifacts.profile.label(),
        artifacts.status_json_path.display()
    );
    if let Some(phase) = last_status.phase.as_deref() {
        message.push_str(&format!(" | last phase={phase}"));
    }
    if let Some(text) = last_status
        .message
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        message.push_str(&format!(" | message={text}"));
    }
    message.push_str(&format!(" | log={}", artifacts.agent_log_path.display()));
    Err(anyhow!(message))
}

fn read_status(path: &Path) -> Result<Option<DumpSessionStatus>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading status {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<DumpSessionStatus>(&raw) {
        Ok(status) => Ok(Some(status)),
        Err(_) => Ok(None),
    }
}

fn process_dump_file_with_retry(
    path: &Path,
    timeout: Duration,
) -> Result<dump_report::ProcessedDump> {
    let start = Instant::now();
    let mut last_error = None;

    while start.elapsed() < timeout {
        match dump_report::process_dump_file(path) {
            Ok(processed) => return Ok(processed),
            Err(err) => {
                let message = err.to_string();
                let retryable = message.contains("dump file does not contain")
                    || message.contains("reading dump file")
                    || message.contains("replacing")
                    || message.contains("writing");
                last_error = Some(err);
                if !retryable {
                    break;
                }
                thread::sleep(Duration::from_millis(400));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("dump post-processing timed out")))
}

fn find_jvm_module(pid: u32) -> Result<PathBuf> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };
    if snapshot.is_invalid() {
        return Err(anyhow!("Unable to create module snapshot"));
    }

    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut found = None;
    let mut has_entry = unsafe { Module32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        if let Some(path) = extract_path(&entry.szExePath) {
            if path
                .to_string_lossy()
                .to_ascii_lowercase()
                .ends_with("jvm.dll")
            {
                found = Some(path);
                break;
            }
        }
        has_entry = unsafe { Module32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }
    found.ok_or_else(|| anyhow!("Could not find jvm.dll in target process"))
}

fn runtime_home_from_jvm(jvm_path: &Path) -> Result<PathBuf> {
    jvm_path
        .parent()
        .and_then(|value| value.parent())
        .and_then(|value| value.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Could not derive runtime home from {}", jvm_path.display()))
}

fn detect_java_major(jvm_path: &Path, runtime_home: &Path) -> Result<u32> {
    if let Some(major) = parse_java_major_from_release(runtime_home)? {
        return Ok(major);
    }
    parse_java_major_from_path(jvm_path).ok_or_else(|| {
        anyhow!(
            "Failed to determine Java version from {}",
            jvm_path.display()
        )
    })
}

fn parse_java_major_from_release(runtime_home: &Path) -> Result<Option<u32>> {
    let release = runtime_home.join("release");
    if !release.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&release)
        .with_context(|| format!("reading release file {}", release.display()))?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("JAVA_VERSION=\"") {
            if let Some(end) = value.find('"') {
                let version = &value[..end];
                let cleaned = version.strip_prefix("1.").unwrap_or(version);
                let major = cleaned
                    .split(['.', '_'])
                    .next()
                    .and_then(|token| token.parse::<u32>().ok());
                if major.is_some() {
                    return Ok(major);
                }
            }
        }
    }
    Ok(None)
}

fn parse_java_major_from_path(jvm_path: &Path) -> Option<u32> {
    let lower = jvm_path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("1.8") || lower.contains("jre1.8") || lower.contains("java-8") {
        return Some(8);
    }

    for segment in lower.split(['\\', '/', '-', '_']) {
        if let Ok(major) = segment.parse::<u32>() {
            if major >= 8 {
                return Some(major);
            }
        }
    }
    None
}

fn detect_target_arch(jvm_path: &Path) -> TargetArch {
    if !cfg!(target_pointer_width = "64") {
        return TargetArch::X86;
    }

    let lower = jvm_path.to_string_lossy().to_ascii_lowercase();
    if lower.contains("program files (x86)")
        || lower.contains("\\x86\\")
        || lower.contains("\\wow64\\")
    {
        TargetArch::X86
    } else {
        TargetArch::X64
    }
}

fn current_arch() -> TargetArch {
    if cfg!(target_pointer_width = "64") {
        TargetArch::X64
    } else {
        TargetArch::X86
    }
}

fn find_runtime_jcmd(runtime_home: &Path) -> Option<PathBuf> {
    let candidates = [
        runtime_home.join("bin").join("jcmd.exe"),
        runtime_home
            .parent()
            .map(|value| value.join("bin").join("jcmd.exe"))
            .unwrap_or_default(),
    ];
    candidates.into_iter().find(|path| path.exists())
}

fn find_external_jcmd(runtime_home: &Path) -> Option<PathBuf> {
    if let Some(runtime_jcmd) = find_runtime_jcmd(runtime_home) {
        return Some(runtime_jcmd);
    }

    let mut candidates = Vec::new();
    for env_name in [
        "JAVA_HOME",
        "JDK_HOME",
        "JAVA17_HOME",
        "JAVA21_HOME",
        "JAVA8_HOME",
    ] {
        if let Some(root) = std::env::var_os(env_name) {
            candidates.push(PathBuf::from(root).join("bin").join("jcmd.exe"));
        }
    }
    candidates.extend([
        PathBuf::from(r"C:\Program Files\Eclipse Adoptium"),
        PathBuf::from(r"C:\Program Files\Java"),
    ]);

    for candidate in candidates {
        if candidate.is_file() {
            return Some(candidate);
        }
        if candidate.is_dir() {
            if let Ok(entries) = fs::read_dir(&candidate) {
                for entry in entries.flatten() {
                    let path = entry.path().join("bin").join("jcmd.exe");
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

fn attach_with_jcmd(
    pid: u32,
    artifacts: &ProfileArtifacts,
    agent_path: &Path,
    jcmd_path: &Path,
) -> Result<()> {
    let output = Command::new(jcmd_path)
        .arg(pid.to_string())
        .arg("JVMTI.agent_load")
        .arg(agent_path)
        .arg(&artifacts.config_path)
        .output()
        .with_context(|| format!("running {}", jcmd_path.display()))?;
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!(
        "jcmd attach failed: status={} stdout={} stderr={}",
        output.status,
        stdout.trim(),
        stderr.trim()
    ))
}

#[derive(Clone, Copy)]
enum RemoteThreadKind {
    CreateRemoteThread,
    NtCreateThreadEx,
}

type NtCreateThreadExFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut c_void,
    HANDLE,
    *mut c_void,
    *mut c_void,
    u32,
    usize,
    usize,
    usize,
    *mut c_void,
) -> i32;

fn inject_agent_native(
    pid: u32,
    runtime: &DetectedRuntime,
    session_id: &str,
    artifacts: &ProfileArtifacts,
    agent_path: &Path,
    thread_kind: RemoteThreadKind,
    transport_mode: TransportMode,
) -> Result<()> {
    let desired_access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;
    let process = unsafe { OpenProcess(desired_access, false, pid)? };
    if process.is_invalid() {
        return Err(anyhow!("Failed to open target process (PID {pid})"));
    }

    let result = inject_agent_native_inner(
        process,
        pid,
        runtime,
        session_id,
        artifacts,
        agent_path,
        thread_kind,
        transport_mode,
    );
    unsafe {
        let _ = CloseHandle(process);
    }
    result
}

fn inject_agent_native_inner(
    process: HANDLE,
    pid: u32,
    runtime: &DetectedRuntime,
    session_id: &str,
    artifacts: &ProfileArtifacts,
    agent_path: &Path,
    thread_kind: RemoteThreadKind,
    transport_mode: TransportMode,
) -> Result<()> {
    let wide_path = to_wide(agent_path);
    let remote_path = write_remote_bytes(process, wide_path.as_ptr() as _, wide_path.len() * 2)?;

    let kernel32 = unsafe { GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr()))? };
    let load_library = unsafe { GetProcAddress(kernel32, s!("LoadLibraryW")) }
        .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW) failed"))?;

    let load_thread = spawn_remote_thread(
        process,
        load_library as *mut c_void,
        remote_path,
        thread_kind,
    )?;
    wait_for_thread(load_thread, REMOTE_THREAD_TIMEOUT_MS, "LoadLibraryW")?;

    let mut load_exit: u32 = 0;
    if unsafe { GetExitCodeThread(load_thread, &mut load_exit).is_ok() } && load_exit == 0 {
        unsafe {
            let _ = CloseHandle(load_thread);
            let _ = VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        }
        return Err(anyhow!(
            "Remote LoadLibraryW failed for {}",
            agent_path.display()
        ));
    }
    unsafe {
        let _ = CloseHandle(load_thread);
        let _ = VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    }

    let remote_module = find_remote_module_base(pid, agent_path)?
        .ok_or_else(|| anyhow!("Injected module not found in target after LoadLibraryW"))?;
    let local_module = unsafe { LoadLibraryW(PCWSTR(to_wide(agent_path).as_ptr()))? };
    let local_start = unsafe { GetProcAddress(local_module, PCSTR::from_raw(b"StartDumpSession\0".as_ptr())) }
        .ok_or_else(|| anyhow!("StartDumpSession export not found"))?;
    let offset = (local_start as usize).saturating_sub(local_module.0 as usize);
    let remote_start = (remote_module + offset) as *mut c_void;

    let remote_config = artifacts.to_remote_config(
        session_id,
        runtime,
        pid,
        transport_mode,
    );
    let remote_cfg_mem = write_remote_bytes(
        process,
        &remote_config as *const RemoteDumpSessionConfig as *const c_void,
        size_of::<RemoteDumpSessionConfig>(),
    )?;

    let start_thread = spawn_remote_thread(process, remote_start, remote_cfg_mem, thread_kind)?;
    wait_for_thread(start_thread, REMOTE_THREAD_TIMEOUT_MS, "StartDumpSession")?;
    let mut start_exit: u32 = 0;
    let _ = unsafe { GetExitCodeThread(start_thread, &mut start_exit) };

    unsafe {
        let _ = CloseHandle(start_thread);
        let _ = VirtualFreeEx(process, remote_cfg_mem, 0, MEM_RELEASE);
    }

    if start_exit != 0 {
        return Err(anyhow!("StartDumpSession returned {start_exit}"));
    }
    Ok(())
}

fn write_remote_bytes(process: HANDLE, source: *const c_void, size: usize) -> Result<*mut c_void> {
    let remote = unsafe {
        VirtualAllocEx(
            process,
            None,
            size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        return Err(anyhow!("VirtualAllocEx failed"));
    }

    if let Err(err) = unsafe { WriteProcessMemory(process, remote, source, size, None) } {
        unsafe {
            let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        return Err(anyhow!("WriteProcessMemory failed: {err}"));
    }

    Ok(remote)
}

fn spawn_remote_thread(
    process: HANDLE,
    start: *mut c_void,
    parameter: *mut c_void,
    kind: RemoteThreadKind,
) -> Result<HANDLE> {
    match kind {
        RemoteThreadKind::CreateRemoteThread => unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                Some(std::mem::transmute(start)),
                Some(parameter as *const _),
                0,
                None,
            )
            .map_err(|err| anyhow!("CreateRemoteThread failed: {err}"))
        },
        RemoteThreadKind::NtCreateThreadEx => spawn_remote_thread_nt(process, start, parameter),
    }
}

fn spawn_remote_thread_nt(
    process: HANDLE,
    start: *mut c_void,
    parameter: *mut c_void,
) -> Result<HANDLE> {
    let ntdll = unsafe { GetModuleHandleA(PCSTR::from_raw(b"ntdll.dll\0".as_ptr()))? };
    let proc = unsafe { GetProcAddress(ntdll, PCSTR::from_raw(b"NtCreateThreadEx\0".as_ptr())) }
        .ok_or_else(|| anyhow!("GetProcAddress(NtCreateThreadEx) failed"))?;
    let nt_create: NtCreateThreadExFn = unsafe { std::mem::transmute(proc) };

    let mut thread = HANDLE::default();
    let status = unsafe {
        nt_create(
            &mut thread,
            0x1FFFFF,
            std::ptr::null_mut(),
            process,
            start,
            parameter,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    };
    if status < 0 || thread.is_invalid() {
        return Err(anyhow!(
            "NtCreateThreadEx failed with status 0x{status:08x}"
        ));
    }
    Ok(thread)
}

fn wait_for_thread(thread: HANDLE, timeout_ms: u32, label: &str) -> Result<()> {
    let wait = unsafe { WaitForSingleObject(thread, timeout_ms) };
    if wait == WAIT_OBJECT_0 {
        Ok(())
    } else {
        Err(anyhow!("{label} thread wait failed"))
    }
}

fn find_remote_module_base(pid: u32, target_path: &Path) -> Result<Option<usize>> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };
    if snapshot.is_invalid() {
        return Err(anyhow!("Unable to create module snapshot"));
    }

    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let wanted = normalize_windows_path(target_path);
    let mut found = None;

    let mut has_entry = unsafe { Module32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        if let Some(path) = extract_path(&entry.szExePath) {
            if normalize_windows_path(&path) == wanted {
                found = Some(entry.modBaseAddr as usize);
                break;
            }
        }
        has_entry = unsafe { Module32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }
    Ok(found)
}

fn normalize_windows_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn extract_path(buf: &[u16]) -> Option<PathBuf> {
    let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if nul == 0 {
        return None;
    }
    let s = OsString::from_wide(&buf[..nul]);
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn utf16_buf_to_string(buf: &[u16]) -> String {
    let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..nul])
        .to_string_lossy()
        .trim()
        .to_string()
}

fn to_wide(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn copy_wide_into(target: &mut [u16; SESSION_TEXT_CAP], value: impl AsRef<OsStr>) {
    let mut encoded = value.as_ref().encode_wide().collect::<Vec<_>>();
    if encoded.len() >= SESSION_TEXT_CAP {
        encoded.truncate(SESSION_TEXT_CAP - 1);
    }
    target[..encoded.len()].copy_from_slice(&encoded);
    target[encoded.len()] = 0;
}

fn bytes_to_gb(bytes: u64) -> f64 {
    ((bytes as f64 / 1024_f64 / 1024_f64 / 1024_f64) * 10.0).round() / 10.0
}
