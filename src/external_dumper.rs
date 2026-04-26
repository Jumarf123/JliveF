use anyhow::{Context, Result, anyhow};
use chrono::Local;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

const SA_HELPER_CLASS: &str = "ExternalSaDump";
const SA_HELPER_SOURCE: &str = include_str!("../external_dumper/sa_helper/ExternalSaDump.java");
const SA_TIMEOUT: Duration = Duration::from_secs(300);
const SA_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
struct RuntimeInfo {
    java_major: Option<u32>,
    java_version: Option<String>,
    runtime_home: PathBuf,
    jvm_path: PathBuf,
    toolchain: JavaToolchain,
}

#[derive(Debug, Clone)]
struct JavaToolchain {
    java_path: PathBuf,
    javac_path: Option<PathBuf>,
    runtime_home: PathBuf,
    java_major: Option<u32>,
    java_version: Option<String>,
    launch_mode: HelperLaunchMode,
    sa_api_mode: SaApiMode,
    disable_sa_version_check: bool,
    origin: String,
}

#[derive(Debug, Clone)]
enum SaApiMode {
    Modules,
    LegacyClasspath { sa_jdi_jar: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperLaunchMode {
    SourceFile,
    CompiledClass,
}

impl HelperLaunchMode {
    fn label(self) -> &'static str {
        match self {
            Self::SourceFile => "java source-file mode",
            Self::CompiledClass => "javac + classpath",
        }
    }
}

#[derive(Debug)]
struct HelperFiles {
    helper_dir: PathBuf,
    source_path: PathBuf,
    stderr_path: PathBuf,
}

pub fn run_for_pid(pid: u32) -> Result<PathBuf> {
    println!("External dumper alternative: checking Java toolchain and dependencies...");
    let runtime =
        detect_runtime(pid).context("detecting target runtime for external dumper alternative")?;
    let output_path = build_output_path(pid)?;
    let helper_files = stage_helper_source(pid)?;

    let dump_result = run_sa_dump(pid, &runtime.toolchain, &helper_files, &output_path);

    let _ = fs::remove_file(&helper_files.source_path);
    let _ = fs::remove_dir_all(&helper_files.helper_dir);

    dump_result?;

    let dumped_classes = count_dumped_classes(&output_path)?;
    println!("Target PID: {}", pid);
    println!(
        "Detected runtime: Java {} via {}",
        display_java_target(runtime.java_major, runtime.java_version.as_deref()),
        runtime.jvm_path.display()
    );
    println!("Runtime home: {}", runtime.runtime_home.display());
    println!("Using java: {}", runtime.toolchain.java_path.display());
    if let Some(javac_path) = &runtime.toolchain.javac_path {
        println!("Using javac: {}", javac_path.display());
    }
    println!(
        "Toolchain Java version: {}",
        display_optional_version(runtime.toolchain.java_version.as_deref())
    );
    println!("Toolchain origin: {}", runtime.toolchain.origin);
    println!(
        "Helper launch mode: {}",
        runtime.toolchain.launch_mode.label()
    );
    if runtime.toolchain.disable_sa_version_check {
        println!(
            "SA version check: disabled for fallback compatibility (target {}, toolchain {}).",
            display_optional_version(runtime.java_version.as_deref()),
            display_optional_version(runtime.toolchain.java_version.as_deref())
        );
    }
    println!("Classes dumped: {}", dumped_classes);
    println!("Output: {}", output_path.display());

    Ok(output_path)
}

fn detect_runtime(pid: u32) -> Result<RuntimeInfo> {
    let jvm_path = find_jvm_module(pid)?;
    let runtime_home = runtime_home_from_jvm(&jvm_path)?;
    let java_version = parse_java_version_from_release(&runtime_home)?;
    let java_major = parse_java_major_from_release(&runtime_home)?;
    let toolchain = resolve_toolchain(&runtime_home, java_major, java_version.as_deref())?;

    Ok(RuntimeInfo {
        java_major,
        java_version,
        runtime_home,
        jvm_path,
        toolchain,
    })
}

fn resolve_toolchain(
    runtime_home: &Path,
    target_major: Option<u32>,
    target_version: Option<&str>,
) -> Result<JavaToolchain> {
    let mut candidates = collect_sorted_toolchains(runtime_home, target_major, target_version);
    if let Some(toolchain) = find_exact_toolchain(&candidates, target_version) {
        return Ok(toolchain);
    }

    if target_version.is_some() {
        println!(
            "External dumper alternative: exact JDK match not found for {}. Trying automatic installation...",
            display_java_target(target_major, target_version)
        );
        let install_report = attempt_winget_install(target_major, target_version)?;
        candidates = collect_sorted_toolchains(runtime_home, target_major, target_version);
        if let Some(toolchain) = find_exact_toolchain(&candidates, target_version) {
            return Ok(toolchain);
        }

        if let Some(mut toolchain) = find_major_compatible_toolchain(&candidates, target_major) {
            toolchain.disable_sa_version_check =
                should_disable_sa_version_check(target_version, toolchain.java_version.as_deref());
            if toolchain.disable_sa_version_check {
                println!(
                    "External dumper alternative: exact JDK version {} is unavailable. Falling back to {} from {} with SA version check disabled.",
                    display_optional_version(target_version),
                    display_optional_version(toolchain.java_version.as_deref()),
                    toolchain.origin
                );
            }
            return Ok(toolchain);
        }

        let install_note = match install_report {
            Some(package_id) => format!(
                " Tried to install `{package_id}` via winget, but no compatible JDK was discovered afterwards."
            ),
            None => " Automatic installation is unavailable in this environment.".to_string(),
        };

        return Err(anyhow!(
            "Could not locate a compatible JDK for external dump. Target Java: {}. \
Checked target runtime, JAVA_HOME/JDK_HOME, PATH and common install directories. \
Required dependencies: `java.exe` with Serviceability Agent support and either `javac.exe` \
or Java 11+ source-file mode.{}",
            display_java_target(target_major, target_version),
            install_note
        ));
    }

    if let Some(toolchain) = find_major_compatible_toolchain(&candidates, target_major) {
        return Ok(toolchain);
    }

    println!(
        "External dumper alternative: compatible JDK not found for Java {}. Trying automatic installation...",
        display_java_major(target_major)
    );
    let install_report = attempt_winget_install(target_major, target_version)?;
    let candidates = collect_sorted_toolchains(runtime_home, target_major, target_version);
    if let Some(toolchain) = find_major_compatible_toolchain(&candidates, target_major) {
        return Ok(toolchain);
    }

    let install_note = match install_report {
        Some(package_id) => format!(
            " Tried to install `{package_id}` via winget, but no compatible JDK was discovered afterwards."
        ),
        None => " Automatic installation is unavailable in this environment.".to_string(),
    };

    Err(anyhow!(
        "Could not locate a compatible JDK for external dump. Target Java: {}. \
Checked target runtime, JAVA_HOME/JDK_HOME, PATH and common install directories. \
Required dependencies: `java.exe` with Serviceability Agent support and either `javac.exe` \
or Java 11+ source-file mode.{}",
        display_java_target(target_major, target_version),
        install_note
    ))
}

fn collect_sorted_toolchains(
    runtime_home: &Path,
    target_major: Option<u32>,
    target_version: Option<&str>,
) -> Vec<JavaToolchain> {
    let mut candidates = collect_toolchain_candidates(runtime_home);
    candidates.sort_by_key(|candidate| {
        toolchain_sort_key(candidate, runtime_home, target_major, target_version)
    });
    candidates
}

fn find_exact_toolchain(
    candidates: &[JavaToolchain],
    target_version: Option<&str>,
) -> Option<JavaToolchain> {
    target_version.and_then(|expected| {
        candidates
            .iter()
            .find(|candidate| {
                java_versions_match_exact(Some(expected), candidate.java_version.as_deref())
            })
            .cloned()
    })
}

fn find_major_compatible_toolchain(
    candidates: &[JavaToolchain],
    target_major: Option<u32>,
) -> Option<JavaToolchain> {
    if let Some(expected) = target_major {
        candidates
            .iter()
            .find(|candidate| candidate.java_major == Some(expected))
            .cloned()
    } else {
        candidates.first().cloned()
    }
}

fn collect_toolchain_candidates(runtime_home: &Path) -> Vec<JavaToolchain> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();

    add_candidate_root(
        &mut roots,
        &mut seen,
        runtime_home.to_path_buf(),
        "target runtime".to_string(),
    );
    if let Some(parent) = runtime_home.parent() {
        add_candidate_root(
            &mut roots,
            &mut seen,
            parent.to_path_buf(),
            "target runtime parent".to_string(),
        );
    }

    for env_name in [
        "JAVA_HOME",
        "JDK_HOME",
        "JAVA17_HOME",
        "JAVA21_HOME",
        "JAVA11_HOME",
        "JAVA8_HOME",
    ] {
        if let Some(root) = std::env::var_os(env_name) {
            add_candidate_root(
                &mut roots,
                &mut seen,
                PathBuf::from(root),
                format!("environment variable {env_name}"),
            );
        }
    }

    for tool in ["java", "javac"] {
        for location in command_locations(tool) {
            if let Some(root) = location.parent().and_then(|value| value.parent()) {
                add_candidate_root(
                    &mut roots,
                    &mut seen,
                    root.to_path_buf(),
                    format!("PATH entry for {tool}"),
                );
            }
        }
    }

    for base in common_java_roots() {
        add_discovered_roots(&mut roots, &mut seen, &base);
    }

    roots
        .into_iter()
        .filter_map(|(root, origin)| inspect_toolchain_candidate(&root, origin))
        .collect()
}

fn attempt_winget_install(
    target_major: Option<u32>,
    target_version: Option<&str>,
) -> Result<Option<String>> {
    let winget = command_locations("winget")
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("winget"));

    if Command::new(&winget)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Ok(None);
    }

    let packages = winget_package_candidates(target_major);

    if let Some(target_version) = target_version {
        let mut exact_version_seen = false;
        for package_id in &packages {
            let Some(package_version) =
                find_matching_winget_version(&winget, package_id, target_version)?
            else {
                continue;
            };

            exact_version_seen = true;
            println!(
                "External dumper alternative: installing exact dependency via winget (`{package_id}` {package_version})..."
            );
            if install_winget_package(&winget, package_id, Some(&package_version))? {
                println!(
                    "External dumper alternative: dependency installation finished for `{package_id}` version `{package_version}`."
                );
                return Ok(Some(format!("{package_id} {package_version}")));
            }
        }

        if !exact_version_seen {
            println!(
                "External dumper alternative: winget does not expose an exact package version for target {}. Falling back to latest Java {} package.",
                display_optional_version(Some(target_version)),
                display_java_major(target_major)
            );
        }
    }

    for package_id in packages {
        println!(
            "External dumper alternative: installing missing dependency via winget (`{package_id}`)..."
        );
        if install_winget_package(&winget, &package_id, None)? {
            println!(
                "External dumper alternative: dependency installation finished for `{package_id}`."
            );
            return Ok(Some(package_id));
        }
    }

    Ok(None)
}

fn winget_package_candidates(target_major: Option<u32>) -> Vec<String> {
    let major = target_major.unwrap_or(17);
    let mut ids = Vec::new();

    match major {
        8 => {
            ids.push("EclipseAdoptium.Temurin.8.JDK".to_string());
            ids.push("Azul.Zulu.8.JDK".to_string());
        }
        11 => {
            ids.push("Microsoft.OpenJDK.11".to_string());
            ids.push("EclipseAdoptium.Temurin.11.JDK".to_string());
            ids.push("Azul.Zulu.11.JDK".to_string());
        }
        17 => {
            ids.push("Microsoft.OpenJDK.17".to_string());
            ids.push("EclipseAdoptium.Temurin.17.JDK".to_string());
            ids.push("Azul.Zulu.17.JDK".to_string());
        }
        21 => {
            ids.push("Microsoft.OpenJDK.21".to_string());
            ids.push("EclipseAdoptium.Temurin.21.JDK".to_string());
            ids.push("Azul.Zulu.21.JDK".to_string());
        }
        _ => {}
    }

    ids.push(format!("Azul.Zulu.{major}.JDK"));
    ids.push(format!("EclipseAdoptium.Temurin.{major}.JDK"));
    ids.push(format!("BellSoft.LibericaJDK.{major}"));

    let mut dedup = HashSet::new();
    ids.into_iter()
        .filter(|id| dedup.insert(id.clone()))
        .collect()
}

fn inspect_toolchain_candidate(root: &Path, origin: String) -> Option<JavaToolchain> {
    let (runtime_home, java_path) = locate_java_binary(root)?;
    let java_version = parse_java_version_from_release(&runtime_home)
        .ok()
        .flatten()
        .or_else(|| probe_java_version(&java_path).ok().flatten());
    let java_major = java_version
        .as_deref()
        .and_then(parse_java_major_from_version_string)
        .or_else(|| probe_java_major(&java_path).ok().flatten());
    let sa_api_mode = detect_sa_api_mode(&runtime_home, &java_path)?;
    let javac_path = locate_javac_binary(root, &runtime_home);
    let launch_mode = if javac_path.is_some() {
        Some(HelperLaunchMode::CompiledClass)
    } else if supports_source_launch(java_major) {
        Some(HelperLaunchMode::SourceFile)
    } else {
        None
    }?;

    Some(JavaToolchain {
        java_path,
        javac_path,
        runtime_home,
        java_major,
        java_version,
        launch_mode,
        sa_api_mode,
        disable_sa_version_check: false,
        origin,
    })
}

fn detect_sa_api_mode(runtime_home: &Path, java_path: &Path) -> Option<SaApiMode> {
    if java_supports_hotspot_agent(java_path) {
        return Some(SaApiMode::Modules);
    }

    find_sa_jdi_jar(runtime_home).map(|sa_jdi_jar| SaApiMode::LegacyClasspath { sa_jdi_jar })
}

fn locate_java_binary(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let direct = root.join("bin").join("java.exe");
    if direct.is_file() {
        return Some((root.to_path_buf(), direct));
    }

    let bundled_jre = root.join("jre").join("bin").join("java.exe");
    if bundled_jre.is_file() {
        return Some((root.join("jre"), bundled_jre));
    }

    None
}

fn locate_javac_binary(root: &Path, runtime_home: &Path) -> Option<PathBuf> {
    let direct = root.join("bin").join("javac.exe");
    if direct.is_file() {
        return Some(direct);
    }

    let runtime = runtime_home.join("bin").join("javac.exe");
    if runtime.is_file() {
        return Some(runtime);
    }

    runtime_home
        .parent()
        .map(|value| value.join("bin").join("javac.exe"))
        .filter(|value| value.is_file())
}

fn find_sa_jdi_jar(runtime_home: &Path) -> Option<PathBuf> {
    let direct = runtime_home.join("lib").join("sa-jdi.jar");
    if direct.is_file() {
        return Some(direct);
    }

    runtime_home
        .parent()
        .map(|value| value.join("lib").join("sa-jdi.jar"))
        .filter(|value| value.is_file())
}

fn supports_source_launch(java_major: Option<u32>) -> bool {
    java_major.is_some_and(|major| major >= 11)
}

fn toolchain_sort_key(
    candidate: &JavaToolchain,
    runtime_home: &Path,
    target_major: Option<u32>,
    target_version: Option<&str>,
) -> (u8, u8, u8, u8, u8, String) {
    let version_score = match target_version {
        Some(expected) => match candidate.java_version.as_deref() {
            Some(found) if java_versions_match_exact(Some(expected), Some(found)) => 0,
            Some(_) => 1,
            None => 2,
        },
        None => 0,
    };
    let major_score = match (target_major, candidate.java_major) {
        (Some(expected), Some(found)) if expected == found => 0,
        (Some(_), Some(_)) => 1,
        (Some(_), None) => 2,
        (None, _) => 0,
    };
    let runtime_score = if path_like_eq(&candidate.runtime_home, runtime_home)
        || candidate.runtime_home.starts_with(runtime_home)
        || runtime_home.starts_with(&candidate.runtime_home)
    {
        0
    } else {
        1
    };
    let mode_score = match candidate.launch_mode {
        HelperLaunchMode::CompiledClass => 0,
        HelperLaunchMode::SourceFile => 1,
    };
    let sa_score = match candidate.sa_api_mode {
        SaApiMode::Modules => 0,
        SaApiMode::LegacyClasspath { .. } => 1,
    };

    (
        version_score,
        major_score,
        runtime_score,
        mode_score,
        sa_score,
        candidate.origin.to_ascii_lowercase(),
    )
}

fn add_discovered_roots(
    roots: &mut Vec<(PathBuf, String)>,
    seen: &mut HashSet<String>,
    base: &Path,
) {
    if !base.is_dir() {
        return;
    }

    add_candidate_root(
        roots,
        seen,
        base.to_path_buf(),
        format!("common Java root {}", base.display()),
    );

    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            add_candidate_root(
                roots,
                seen,
                path,
                format!("discovered under {}", base.display()),
            );
        }
    }
}

fn add_candidate_root(
    roots: &mut Vec<(PathBuf, String)>,
    seen: &mut HashSet<String>,
    path: PathBuf,
    origin: String,
) {
    let key = path.to_string_lossy().to_ascii_lowercase();
    if seen.insert(key) {
        roots.push((path, origin));
    }
}

fn common_java_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for base in [r"C:\Program Files", r"C:\Program Files (x86)"] {
        for suffix in [
            "Java",
            "Microsoft",
            "Eclipse Adoptium",
            "Zulu",
            "BellSoft",
            "Semeru",
            "SapMachine",
        ] {
            roots.push(PathBuf::from(base).join(suffix));
        }
    }
    roots
}

fn command_locations(tool: &str) -> Vec<PathBuf> {
    let output = Command::new("where.exe").arg(tool).output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn java_supports_hotspot_agent(java_path: &Path) -> bool {
    Command::new(java_path)
        .arg("--describe-module")
        .arg("jdk.hotspot.agent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn probe_java_major(java_path: &Path) -> Result<Option<u32>> {
    let output = Command::new(java_path)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("probing Java version via {}", java_path.display()))?;

    let text = String::from_utf8_lossy(&output.stderr);
    Ok(parse_java_major_from_version_output(&text))
}

fn probe_java_version(java_path: &Path) -> Result<Option<String>> {
    let output = Command::new(java_path)
        .arg("-fullversion")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("probing Java full version via {}", java_path.display()))?;

    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_java_version_from_version_output(&text))
}

fn parse_java_version_from_version_output(value: &str) -> Option<String> {
    value
        .split('"')
        .nth(1)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_java_major_from_version_output(value: &str) -> Option<u32> {
    let quoted = value
        .split('"')
        .nth(1)
        .map(str::trim)
        .filter(|text| !text.is_empty())?;
    parse_java_major_from_version_string(quoted)
}

fn parse_java_major_from_version_string(value: &str) -> Option<u32> {
    let cleaned = value.strip_prefix("1.").unwrap_or(value);
    cleaned
        .split(['.', '_', '-'])
        .next()
        .and_then(|token| token.parse::<u32>().ok())
}

fn parse_java_version_from_release(runtime_home: &Path) -> Result<Option<String>> {
    let release = runtime_home.join("release");
    if !release.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&release)
        .with_context(|| format!("reading release file {}", release.display()))?;
    let mut runtime_version = None;
    let mut short_version = None;

    for line in content.lines() {
        if let Some(value) = extract_release_value(line, "JAVA_RUNTIME_VERSION") {
            runtime_version = Some(value.to_string());
        } else if let Some(value) = extract_release_value(line, "JAVA_VERSION") {
            short_version = Some(value.to_string());
        }
    }

    Ok(runtime_version.or(short_version))
}

fn display_java_major(java_major: Option<u32>) -> String {
    java_major
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn display_optional_version(version: Option<&str>) -> String {
    version
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn display_java_target(java_major: Option<u32>, java_version: Option<&str>) -> String {
    java_version
        .map(|value| value.to_string())
        .unwrap_or_else(|| display_java_major(java_major))
}

fn extract_release_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=\"");
    let value = line.strip_prefix(&prefix)?;
    let end = value.find('"')?;
    Some(&value[..end])
}

fn normalize_java_version(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    if let Some((release, build)) = trimmed.split_once('+') {
        let release = join_numeric_tokens(&numeric_version_tokens(release))?;
        let build = leading_numeric_token(build)?;
        return Some(format!("{release}+{build}"));
    }

    let tokens = numeric_version_tokens(trimmed);
    if tokens.is_empty() {
        return None;
    }

    if tokens.len() >= 4 && tokens[0] >= 9 {
        let release = join_numeric_tokens(&tokens[..tokens.len() - 1])?;
        return Some(format!("{release}+{}", tokens[tokens.len() - 1]));
    }

    join_numeric_tokens(&tokens)
}

fn java_versions_match_exact(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => normalize_java_version(left) == normalize_java_version(right),
        _ => false,
    }
}

fn should_disable_sa_version_check(
    target_version: Option<&str>,
    toolchain_version: Option<&str>,
) -> bool {
    target_version.is_some() && !java_versions_match_exact(target_version, toolchain_version)
}

fn numeric_version_tokens(value: &str) -> Vec<u32> {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|token| !token.is_empty())
        .filter_map(|token| token.parse::<u32>().ok())
        .collect()
}

fn join_numeric_tokens(tokens: &[u32]) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }

    Some(
        tokens
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn leading_numeric_token(value: &str) -> Option<u32> {
    let digits: String = value.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u32>().ok()
    }
}

fn winget_version_candidates(target_version: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let trimmed = target_version.trim().trim_matches('"');
    if !trimmed.is_empty() {
        versions.push(trimmed.to_string());
    }

    if let Some(normalized) = normalize_java_version(trimmed) {
        if let Some((release, build)) = normalized.split_once('+') {
            versions.push(format!("{release}.{build}"));
            versions.push(release.to_string());
        } else {
            versions.push(normalized);
        }
    }

    let mut dedup = HashSet::new();
    versions
        .into_iter()
        .filter(|version| dedup.insert(version.clone()))
        .collect()
}

fn find_matching_winget_version(
    winget: &Path,
    package_id: &str,
    target_version: &str,
) -> Result<Option<String>> {
    let output = Command::new(winget)
        .args([
            "show",
            "--id",
            package_id,
            "-e",
            "--versions",
            "--source",
            "winget",
        ])
        .output()
        .with_context(|| format!("querying winget versions for {package_id}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let available_versions = parse_winget_versions_output(&String::from_utf8_lossy(&output.stdout));
    for candidate in winget_version_candidates(target_version) {
        if available_versions.iter().any(|value| value == &candidate) {
            return Ok(Some(candidate));
        }
    }

    let target_normalized = normalize_java_version(target_version);
    Ok(available_versions
        .into_iter()
        .find(|version| normalize_java_version(version) == target_normalized))
}

fn parse_winget_versions_output(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| line.chars().any(|ch| ch.is_ascii_digit()))
        .filter(|line| {
            line.chars()
                .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '+' | '-' | '_'))
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn install_winget_package(winget: &Path, package_id: &str, version: Option<&str>) -> Result<bool> {
    let mut command = Command::new(winget);
    command.args([
        "install",
        "--id",
        package_id,
        "-e",
        "--source",
        "winget",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
    ]);
    if let Some(version) = version {
        command.arg("--version").arg(version);
    }

    let status = command
        .status()
        .with_context(|| format!("starting winget install for {package_id}"))?;
    if status.success() {
        return Ok(true);
    }

    println!(
        "External dumper alternative: winget install failed for `{package_id}` with status {status}."
    );
    Ok(false)
}

fn path_like_eq(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn find_jvm_module(pid: u32) -> Result<PathBuf> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };
    if snapshot.is_invalid() {
        return Err(anyhow!("Unable to create module snapshot"));
    }

    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut result = None;
    let mut has_entry = unsafe { Module32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        if let Some(path) = extract_path(&entry.szExePath) {
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if lower.ends_with("jvm.dll") {
                result = Some(path);
                break;
            }
        }
        has_entry = unsafe { Module32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    result.ok_or_else(|| anyhow!("Could not find jvm.dll in target process"))
}

fn runtime_home_from_jvm(jvm_path: &Path) -> Result<PathBuf> {
    jvm_path
        .parent()
        .and_then(|value| value.parent())
        .and_then(|value| value.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Could not derive runtime home from {}", jvm_path.display()))
}

fn parse_java_major_from_release(runtime_home: &Path) -> Result<Option<u32>> {
    Ok(parse_java_version_from_release(runtime_home)?
        .as_deref()
        .and_then(parse_java_major_from_version_string))
}

fn build_output_path(pid: u32) -> Result<PathBuf> {
    let exe_dir = std::env::current_exe()
        .context("resolving current exe path")?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Could not resolve executable directory"))?;
    let output_dir = exe_dir
        .join("results")
        .join("dumper")
        .join("external_alternative");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("creating output dir {}", output_dir.display()))?;
    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    Ok(output_dir.join(format!("external_classes_{}_{}.txt", pid, timestamp)))
}

fn stage_helper_source(pid: u32) -> Result<HelperFiles> {
    let helper_dir = std::env::temp_dir()
        .join("external_dumper_alternative_sa")
        .join(pid.to_string());
    fs::create_dir_all(&helper_dir)
        .with_context(|| format!("creating helper dir {}", helper_dir.display()))?;

    let source_path = helper_dir.join(format!("{SA_HELPER_CLASS}.java"));
    let stderr_path = helper_dir.join("external_dumper.stderr.log");
    fs::write(&source_path, SA_HELPER_SOURCE)
        .with_context(|| format!("writing helper source {}", source_path.display()))?;

    Ok(HelperFiles {
        helper_dir,
        source_path,
        stderr_path,
    })
}

fn run_sa_dump(
    pid: u32,
    toolchain: &JavaToolchain,
    helper_files: &HelperFiles,
    output_path: &Path,
) -> Result<()> {
    if toolchain.launch_mode == HelperLaunchMode::CompiledClass {
        compile_helper(toolchain, helper_files)?;
    }

    let stdout_file = File::create(output_path)
        .with_context(|| format!("creating output file {}", output_path.display()))?;
    let stderr_file = File::create(&helper_files.stderr_path).with_context(|| {
        format!(
            "creating stderr file {}",
            helper_files.stderr_path.display()
        )
    })?;

    let mut child = Command::new(&toolchain.java_path);
    configure_java_command(&mut child, toolchain, helper_files, pid)?;
    child
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let mut child = child
        .spawn()
        .with_context(|| format!("launching SA helper via {}", toolchain.java_path.display()))?;

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("waiting for SA helper")? {
            if status.success() {
                return Ok(());
            }

            let stderr = read_text_file(&helper_files.stderr_path);
            let _ = fs::remove_file(output_path);
            return Err(anyhow!(
                "SA helper failed: status={} stderr={}",
                status,
                stderr.trim()
            ));
        }

        if start.elapsed() > SA_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = read_text_file(&helper_files.stderr_path);
            let _ = fs::remove_file(output_path);
            return Err(anyhow!(
                "SA helper timed out after {} seconds. stderr={}",
                SA_TIMEOUT.as_secs(),
                stderr.trim()
            ));
        }

        thread::sleep(SA_POLL_INTERVAL);
    }
}

fn compile_helper(toolchain: &JavaToolchain, helper_files: &HelperFiles) -> Result<()> {
    let javac_path = toolchain.javac_path.as_ref().ok_or_else(|| {
        anyhow!("javac.exe is required to prepare external dumper alternative helper")
    })?;

    let mut command = Command::new(javac_path);
    configure_javac_command(&mut command, toolchain, helper_files)?;
    let output = command
        .output()
        .with_context(|| format!("launching javac via {}", javac_path.display()))?;

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "Failed to compile `{}` for external dump. {}",
        helper_files.source_path.display(),
        format_command_output(&output)
    ))
}

fn configure_javac_command(
    command: &mut Command,
    toolchain: &JavaToolchain,
    helper_files: &HelperFiles,
) -> Result<()> {
    match &toolchain.sa_api_mode {
        SaApiMode::Modules => append_hotspot_module_args(command),
        SaApiMode::LegacyClasspath { sa_jdi_jar } => {
            command.arg("-cp").arg(sa_jdi_jar);
        }
    }

    command
        .arg("-d")
        .arg(&helper_files.helper_dir)
        .arg(&helper_files.source_path);

    Ok(())
}

fn configure_java_command(
    command: &mut Command,
    toolchain: &JavaToolchain,
    helper_files: &HelperFiles,
    pid: u32,
) -> Result<()> {
    if toolchain.disable_sa_version_check {
        command.arg("-Dsun.jvm.hotspot.runtime.VM.disableVersionCheck=true");
    }

    match (&toolchain.sa_api_mode, toolchain.launch_mode) {
        (SaApiMode::Modules, HelperLaunchMode::SourceFile) => {
            append_hotspot_module_args(command);
            command.arg(&helper_files.source_path);
        }
        (SaApiMode::Modules, HelperLaunchMode::CompiledClass) => {
            append_hotspot_module_args(command);
            command
                .arg("-cp")
                .arg(&helper_files.helper_dir)
                .arg(SA_HELPER_CLASS);
        }
        (SaApiMode::LegacyClasspath { sa_jdi_jar }, HelperLaunchMode::CompiledClass) => {
            command
                .arg("-cp")
                .arg(join_classpath([
                    sa_jdi_jar.as_path(),
                    helper_files.helper_dir.as_path(),
                ]))
                .arg(SA_HELPER_CLASS);
        }
        (SaApiMode::LegacyClasspath { .. }, HelperLaunchMode::SourceFile) => {
            return Err(anyhow!(
                "Legacy Java runtimes require javac.exe for external dump preparation"
            ));
        }
    }

    command.arg(pid.to_string());
    Ok(())
}

fn append_hotspot_module_args(command: &mut Command) {
    command
        .arg("--add-modules")
        .arg("jdk.hotspot.agent")
        .arg("--add-exports")
        .arg("jdk.hotspot.agent/sun.jvm.hotspot=ALL-UNNAMED")
        .arg("--add-exports")
        .arg("jdk.hotspot.agent/sun.jvm.hotspot.oops=ALL-UNNAMED")
        .arg("--add-exports")
        .arg("jdk.hotspot.agent/sun.jvm.hotspot.utilities=ALL-UNNAMED")
        .arg("--add-exports")
        .arg("jdk.hotspot.agent/sun.jvm.hotspot.classfile=ALL-UNNAMED")
        .arg("--add-exports")
        .arg("jdk.hotspot.agent/sun.jvm.hotspot.runtime=ALL-UNNAMED");
}

fn join_classpath<'a>(paths: impl IntoIterator<Item = &'a Path>) -> OsString {
    let mut value = OsString::new();
    let mut first = true;
    for path in paths {
        if !first {
            value.push(";");
        }
        value.push(path.as_os_str());
        first = false;
    }
    value
}

fn format_command_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => format!("process exited with status {}", output.status),
        (false, true) => format!("stdout={stdout}"),
        (true, false) => format!("stderr={stderr}"),
        (false, false) => format!("stdout={stdout} stderr={stderr}"),
    }
}

fn count_dumped_classes(path: &Path) -> Result<usize> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading output file {}", path.display()))?;
    Ok(contents
        .lines()
        .filter(|line| line.starts_with("Class: "))
        .count())
}

fn read_text_file(path: &Path) -> String {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return String::new(),
    };
    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents);
    contents
}

fn extract_path(buf: &[u16]) -> Option<PathBuf> {
    let nul = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if nul == 0 {
        return None;
    }
    let value = OsString::from_wide(&buf[..nul]);
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}
