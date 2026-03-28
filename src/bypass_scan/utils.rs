use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;
use std::{collections::HashMap, collections::HashSet};

use chrono::{Duration, Utc};
use encoding_rs::Encoding;
use rayon::prelude::*;
use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;

use crate::bypass_scan::context::ScanContext;
use crate::bypass_scan::context::ScanProfile;

#[derive(Debug, Clone)]
pub struct EventRecord {
    pub event_id: u32,
    pub provider: String,
    pub time_created: String,
    pub message: String,
    pub raw_xml: String,
}

#[derive(Debug, Clone)]
pub struct EventLogState {
    pub log_name: String,
    pub record_count: Option<u64>,
    pub oldest_record_number: Option<u64>,
    pub file_size_bytes: Option<u64>,
    pub is_enabled: Option<bool>,
    pub log_mode: Option<String>,
    pub log_file_path: Option<String>,
    pub last_write_time_utc: Option<String>,
    pub last_access_time_utc: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UsnJournalState {
    pub volume: String,
    pub available: bool,
    pub missing: bool,
    pub access_denied: bool,
}

#[derive(Debug, Clone)]
pub struct NtfsVolumeMetadata {
    pub volume: String,
    pub ntfs_version: Option<String>,
    pub lfs_version: Option<String>,
    pub mft_valid_data_length: Option<String>,
    pub mft_start_lcn: Option<String>,
    pub mft_mirror_start_lcn: Option<String>,
    pub bytes_per_file_record_segment: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimePrewarmStats {
    pub event_channels_warmed: usize,
    pub candidate_exts_indexed: usize,
    pub candidate_files_indexed: usize,
}

#[derive(Debug, Clone)]
struct ChannelEventCache {
    fetched_raw: usize,
    records: Arc<Vec<EventRecord>>,
}

#[derive(Debug, Clone, Default)]
struct CandidateInventory {
    per_ext: HashMap<String, Vec<(PathBuf, SystemTime)>>,
    indexed_files: usize,
}

const INDEXED_CANDIDATE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "scr", "cpl", "msi", "ocx", "jpg", "jpeg", "png", "gif", "webp", "bmp",
    "txt", "log", "pdf", "mp3", "mp4", "dat",
];

const EVENT_CHANNEL_RAW_MULTIPLIER: usize = 8;
const EVENT_CHANNEL_RAW_MIN: usize = 1200;
const EVENT_CHANNEL_RAW_MAX: usize = 32768;

pub fn run_command(exe: &str, args: &[&str]) -> Option<String> {
    let key = format!("{exe}\u{1F}{}", args.join("\u{1E}"));
    if let Some(cached) = command_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(&key).cloned())
    {
        return Some(cached);
    }

    let output = Command::new(exe).args(args).output().ok()?;
    let mut text = String::new();
    text.push_str(&decode_windows_command_output(exe, &output.stdout));
    if !output.stderr.is_empty() {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&decode_windows_command_output(exe, &output.stderr));
    }

    if let Ok(mut cache) = command_cache().lock() {
        if cache.len() > 800 {
            cache.clear();
        }
        cache.insert(key, text.clone());
    }

    Some(text)
}

fn decode_windows_command_output(exe: &str, bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    if let Some(s) = decode_utf16_output(bytes) {
        return s;
    }

    if let Ok(s) = String::from_utf8(bytes.to_vec()) {
        return s;
    }

    let exe_lower = exe.to_lowercase();
    let preferred_codepages: &[&str] = if exe_lower.contains("fsutil")
        || exe_lower.contains("vssadmin")
        || exe_lower.contains("wmic")
        || exe_lower.contains("bcdedit")
    {
        // These tools commonly use OEM output in RU locale.
        &["ibm866", "windows-1251", "windows-1252"]
    } else {
        // Event/XML-heavy tools are usually better decoded with ANSI first.
        &["windows-1251", "ibm866", "windows-1252"]
    };

    for label in preferred_codepages {
        if let Some(enc) = Encoding::for_label(label.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            let decoded = cow.into_owned();
            if !decoded.trim().is_empty() {
                return decoded;
            }
        }
    }

    String::from_utf8_lossy(bytes).into_owned()
}

fn decode_utf16_output(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        return Some(String::from_utf16_lossy(&u16s));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        return Some(String::from_utf16_lossy(&u16s));
    }

    // Some Windows CLIs emit UTF-16LE without BOM.
    let nul_ratio = bytes
        .iter()
        .step_by(2)
        .filter(|b| **b == 0)
        .count()
        .max(bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count());
    if nul_ratio >= bytes.len() / 4 {
        let u16s = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        return Some(String::from_utf16_lossy(&u16s));
    }

    None
}

pub fn run_powershell(script: &str) -> Option<String> {
    run_command(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
    )
}

pub fn query_event_records(
    channel: &str,
    event_ids: &[u32],
    max_events: usize,
) -> Vec<EventRecord> {
    if event_ids.is_empty() || max_events == 0 {
        return Vec::new();
    }

    let ids = event_ids.iter().copied().collect::<HashSet<_>>();
    let mut target_raw = desired_event_raw_count(max_events);
    let mut expansions = 0usize;

    loop {
        let records = ensure_channel_event_cache(channel, target_raw);
        if records.is_empty() {
            return Vec::new();
        }

        let mut filtered = Vec::with_capacity(max_events.min(records.len()));
        for record in records.iter() {
            if ids.contains(&record.event_id) {
                filtered.push(record.clone());
                if filtered.len() >= max_events {
                    break;
                }
            }
        }

        let cached_meta = channel_event_cache().lock().ok().and_then(|m| {
            m.get(channel)
                .map(|entry| (entry.fetched_raw, entry.records.len()))
        });

        let Some((fetched_raw, actual_count)) = cached_meta else {
            return filtered;
        };

        let source_exhausted = actual_count < fetched_raw;
        if filtered.len() >= max_events
            || filtered.is_empty()
            || source_exhausted
            || fetched_raw >= EVENT_CHANNEL_RAW_MAX
            || expansions >= 1
        {
            return filtered;
        }

        target_raw = (fetched_raw.saturating_mul(2)).min(EVENT_CHANNEL_RAW_MAX);
        expansions += 1;
    }
}

fn desired_event_raw_count(max_events: usize) -> usize {
    max_events
        .saturating_mul(EVENT_CHANNEL_RAW_MULTIPLIER)
        .clamp(EVENT_CHANNEL_RAW_MIN, EVENT_CHANNEL_RAW_MAX)
}

fn ensure_channel_event_cache(channel: &str, target_raw: usize) -> Arc<Vec<EventRecord>> {
    if let Some(existing) = channel_event_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(channel).cloned())
        && existing.fetched_raw >= target_raw
    {
        return existing.records;
    }

    let count_arg = format!("/c:{target_raw}");
    let args = ["qe", channel, "/f:xml", count_arg.as_str(), "/rd:true"];
    let events = Arc::new(
        run_command("wevtutil", &args)
            .map(|xml| parse_event_records(&xml))
            .unwrap_or_default(),
    );

    if let Ok(mut cache) = channel_event_cache().lock() {
        if cache.len() > 80 {
            cache.clear();
        }
        cache.insert(
            channel.to_string(),
            ChannelEventCache {
                fetched_raw: target_raw,
                records: Arc::clone(&events),
            },
        );
    }

    events
}

pub fn query_event_log_state(channel: &str) -> EventLogState {
    if let Some(cached) = event_log_state_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(channel).cloned())
    {
        return cached;
    }

    let escaped_channel = channel.replace('\'', "''");
    let script = format!(
        r#"
$logName = '{escaped_channel}'
try {{
  $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
  [pscustomobject]@{{
    LogName = $log.LogName
    RecordCount = if ($null -ne $log.RecordCount) {{ [Int64]$log.RecordCount }} else {{ $null }}
    OldestRecordNumber = if ($null -ne $log.OldestRecordNumber) {{ [Int64]$log.OldestRecordNumber }} else {{ $null }}
    FileSize = if ($null -ne $log.FileSize) {{ [Int64]$log.FileSize }} else {{ $null }}
    IsEnabled = $log.IsEnabled
    LogMode = if ($null -ne $log.LogMode) {{ $log.LogMode.ToString() }} else {{ $null }}
    LogFilePath = $log.LogFilePath
    LastWriteTimeUtc = if ($null -ne $log.LastWriteTime) {{ $log.LastWriteTime.ToUniversalTime().ToString("o") }} else {{ $null }}
    LastAccessTimeUtc = if ($null -ne $log.LastAccessTime) {{ $log.LastAccessTime.ToUniversalTime().ToString("o") }} else {{ $null }}
    Error = $null
  }} | ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{
    LogName = $logName
    RecordCount = $null
    OldestRecordNumber = $null
    FileSize = $null
    IsEnabled = $null
    LogMode = $null
    LogFilePath = $null
    LastWriteTimeUtc = $null
    LastAccessTimeUtc = $null
    Error = $_.Exception.Message
  }} | ConvertTo-Json -Compress
}}
"#
    );

    let state = run_powershell(&script)
        .and_then(|text| parse_event_log_state_json(&text))
        .map(|mut parsed| {
            if let Some(path) = parsed.log_file_path.clone() {
                let expanded = std::env::vars().fold(path, |acc, (key, value)| {
                    acc.replace(&format!("%{key}%"), &value)
                });
                parsed.log_file_path = Some(expanded);
            }
            parsed
        })
        .unwrap_or_else(|| EventLogState {
            log_name: channel.to_string(),
            record_count: None,
            oldest_record_number: None,
            file_size_bytes: None,
            is_enabled: None,
            log_mode: None,
            log_file_path: None,
            last_write_time_utc: None,
            last_access_time_utc: None,
            error: Some("failed to query event log state".to_string()),
        });

    if let Ok(mut cache) = event_log_state_cache().lock() {
        if cache.len() > 80 {
            cache.clear();
        }
        cache.insert(channel.to_string(), state.clone());
    }

    state
}

pub fn query_event_log_states(channels: &[&str]) -> Vec<EventLogState> {
    channels
        .iter()
        .map(|channel| query_event_log_state(channel))
        .collect()
}

pub fn query_usn_journal_states() -> Vec<UsnJournalState> {
    let volumes = list_windows_drive_roots();
    let mut out = Vec::new();

    for volume in volumes {
        let state = query_usn_journal_state_for_volume(&volume);
        out.push(state);
    }

    out
}

pub fn query_ntfs_volume_metadata() -> Vec<NtfsVolumeMetadata> {
    let volumes = list_windows_drive_roots();
    let mut out = Vec::new();

    for volume in volumes {
        out.push(query_ntfs_volume_metadata_for_volume(&volume));
    }

    out
}

pub fn parse_event_records(xml: &str) -> Vec<EventRecord> {
    let block_re = event_block_re();
    let id_re = event_id_re();
    let provider_re = provider_name_re();
    let time_re = time_created_re();
    let message_re = message_re();
    let data_re = data_re();

    let mut out = Vec::new();

    for cap in block_re.captures_iter(xml) {
        let Some(block_match) = cap.get(0) else {
            continue;
        };
        let block = block_match.as_str().to_string();
        let Some(event_id) = id_re
            .captures(&block)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u32>().ok())
        else {
            continue;
        };

        let provider = provider_re
            .captures(&block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let time_created = time_re
            .captures(&block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(msg) = message_re
            .captures(&block)
            .and_then(|c| c.get(1))
            .map(|m| sanitize_xml_text(m.as_str()))
        {
            msg
        } else {
            let mut parts = Vec::new();
            for d in data_re.captures_iter(&block) {
                if let Some(data) = d.get(1) {
                    let clean = sanitize_xml_text(data.as_str());
                    if !clean.trim().is_empty() {
                        parts.push(clean);
                    }
                }
            }
            parts.join(" | ")
        };

        out.push(EventRecord {
            event_id,
            provider,
            time_created,
            message,
            raw_xml: block,
        });
    }

    out
}

fn event_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<Event\b.*?</Event>").expect("event block regex"))
}

fn event_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<EventID[^>]*>(\d+)</EventID>").expect("event id regex"))
}

fn provider_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"<Provider[^>]*Name=['\"]([^'\"]+)['\"]"#).expect("provider regex")
    })
}

fn time_created_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]"#)
            .expect("time created regex")
    })
}

fn message_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<Message>(.*?)</Message>").expect("message regex"))
}

fn data_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<Data[^>]*>(.*?)</Data>").expect("data regex"))
}

fn sanitize_xml_text(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn extract_event_data_value(raw_xml: &str, data_name: &str) -> Option<String> {
    let needle_double = format!("Name=\"{data_name}\"");
    let needle_single = format!("Name='{data_name}'");
    let name_pos = raw_xml
        .find(&needle_double)
        .or_else(|| raw_xml.find(&needle_single))?;
    let data_tag_start = raw_xml[..name_pos].rfind("<Data")?;
    let tag_end_rel = raw_xml[data_tag_start..].find('>')?;
    let value_start = data_tag_start + tag_end_rel + 1;
    let value_end_rel = raw_xml[value_start..].find("</Data>")?;
    let value_end = value_start + value_end_rel;
    Some(sanitize_xml_text(&raw_xml[value_start..value_end]))
}

pub fn extract_xml_tag_value(raw_xml: &str, tag_name: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)<{}\b[^>]*>(.*?)</{}>"#,
        regex::escape(tag_name),
        regex::escape(tag_name)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(raw_xml)
        .and_then(|cap| cap.get(1))
        .map(|m| sanitize_xml_text(m.as_str()))
}

pub fn collect_candidate_files(
    ctx: &ScanContext,
    exts: &[&str],
    max_files_override: Option<usize>,
) -> Vec<PathBuf> {
    let ext_set = exts
        .iter()
        .map(|e| e.to_lowercase())
        .collect::<HashSet<_>>();
    let max_files = max_files_override.unwrap_or_else(|| ctx.profile.max_file_candidates());

    if let Some(cached) = collect_candidate_files_from_inventory(ctx, &ext_set, max_files) {
        return cached;
    }

    let mut files = Vec::new();
    let cutoff = Utc::now() - Duration::days(ctx.profile.lookback_days());
    let quick_mode = ctx.profile == crate::bypass_scan::context::ScanProfile::Quick;

    let quick_dirs = ctx
        .activity_paths
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect::<Vec<_>>();
    let quick_names = ctx
        .activity_paths
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .map(|n| n.to_lowercase())
        .collect::<HashSet<_>>();

    for path in &ctx.activity_paths {
        if files.len() >= max_files {
            break;
        }
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(OsStr::to_str)
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if !ext_set.contains(&ext) {
            continue;
        }

        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        if meta.len() == 0 || meta.len() > ctx.profile.max_file_size_bytes() {
            continue;
        }

        let Ok(modified) = meta.modified() else {
            continue;
        };
        if chrono::DateTime::<Utc>::from(modified) < cutoff {
            continue;
        }

        files.push((path.to_path_buf(), modified));
    }

    for root in &ctx.scan_roots {
        if !root.exists() {
            continue;
        }

        for entry in WalkDir::new(root)
            .max_depth(ctx.profile.max_walk_depth())
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let ext = path
                .extension()
                .and_then(OsStr::to_str)
                .map(|e| e.to_lowercase())
                .unwrap_or_default();

            if !ext_set.contains(&ext) {
                continue;
            }

            if quick_mode {
                let in_recent_dir = quick_dirs.iter().any(|d| path.starts_with(d));
                let name_match = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| quick_names.contains(&n.to_lowercase()))
                    .unwrap_or(false);
                if !ctx.activity_paths.is_empty() && !in_recent_dir && !name_match {
                    continue;
                }
            }

            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() == 0 || meta.len() > ctx.profile.max_file_size_bytes() {
                continue;
            }

            let Ok(modified) = meta.modified() else {
                continue;
            };
            let modified_utc = chrono::DateTime::<Utc>::from(modified);
            if modified_utc < cutoff {
                continue;
            }

            files.push((path.to_path_buf(), modified));
        }
    }

    files.sort_by_key(|(_, modified)| *modified);
    files.reverse();
    files.dedup_by(|(left, _), (right, _)| left == right);

    files
        .into_iter()
        .take(max_files)
        .map(|(path, _)| path)
        .collect()
}

fn collect_candidate_files_from_inventory(
    ctx: &ScanContext,
    ext_set: &HashSet<String>,
    max_files: usize,
) -> Option<Vec<PathBuf>> {
    if ext_set.is_empty() {
        return Some(Vec::new());
    }

    let indexed_exts = indexed_ext_set();
    if !ext_set.iter().all(|ext| indexed_exts.contains(ext)) {
        return None;
    }

    let key = candidate_inventory_key(ctx);
    let inventory = {
        let mut cache = candidate_inventory_cache().lock().ok()?;
        if !cache.contains_key(&key) {
            cache.insert(key.clone(), build_candidate_inventory(ctx));
        }
        cache.get(&key).cloned()
    }?;

    let mut files = Vec::new();
    for ext in ext_set {
        if let Some(items) = inventory.per_ext.get(ext) {
            files.extend(items.iter().cloned());
        }
    }

    files.sort_by_key(|(_, modified)| *modified);
    files.reverse();
    files.dedup_by(|(left, _), (right, _)| left == right);

    Some(
        files
            .into_iter()
            .take(max_files)
            .map(|(path, _)| path)
            .collect(),
    )
}

fn build_candidate_inventory(ctx: &ScanContext) -> CandidateInventory {
    let indexed_exts = indexed_ext_set();
    let cutoff = Utc::now() - Duration::days(ctx.profile.lookback_days());
    let quick_mode = ctx.profile == ScanProfile::Quick;
    let mut per_ext: HashMap<String, Vec<(PathBuf, SystemTime)>> = HashMap::new();

    let quick_dirs = ctx
        .activity_paths
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect::<Vec<_>>();
    let quick_names = ctx
        .activity_paths
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .map(|n| n.to_lowercase())
        .collect::<HashSet<_>>();

    for path in &ctx.activity_paths {
        if !path.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(OsStr::to_str)
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        if !indexed_exts.contains(&ext) {
            continue;
        }
        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        if meta.len() == 0 || meta.len() > ctx.profile.max_file_size_bytes() {
            continue;
        }
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if chrono::DateTime::<Utc>::from(modified) < cutoff {
            continue;
        }
        per_ext
            .entry(ext)
            .or_default()
            .push((path.to_path_buf(), modified));
    }

    let max_depth = ctx.profile.max_walk_depth();
    let max_size = ctx.profile.max_file_size_bytes();
    let roots_hits = ctx
        .scan_roots
        .par_iter()
        .filter(|root| root.exists())
        .map(|root| {
            let mut hits: Vec<(String, PathBuf, SystemTime)> = Vec::new();
            for entry in WalkDir::new(root)
                .max_depth(max_depth)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                let ext = path
                    .extension()
                    .and_then(OsStr::to_str)
                    .map(|e| e.to_lowercase())
                    .unwrap_or_default();
                if !indexed_exts.contains(&ext) {
                    continue;
                }

                if quick_mode {
                    let in_recent_dir = quick_dirs.iter().any(|d| path.starts_with(d));
                    let name_match = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| quick_names.contains(&n.to_lowercase()))
                        .unwrap_or(false);
                    if !ctx.activity_paths.is_empty() && !in_recent_dir && !name_match {
                        continue;
                    }
                }

                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.len() == 0 || meta.len() > max_size {
                    continue;
                }
                let Ok(modified) = meta.modified() else {
                    continue;
                };
                if chrono::DateTime::<Utc>::from(modified) < cutoff {
                    continue;
                }

                hits.push((ext, path.to_path_buf(), modified));
            }
            hits
        })
        .collect::<Vec<_>>();

    for root_hits in roots_hits {
        for (ext, path, modified) in root_hits {
            per_ext.entry(ext).or_default().push((path, modified));
        }
    }

    let per_ext_cap = match ctx.profile {
        ScanProfile::Quick => ctx.profile.max_file_candidates().max(1024),
        ScanProfile::Deep => ctx.profile.max_file_candidates().max(8192),
    };

    let mut indexed_files = 0usize;
    for items in per_ext.values_mut() {
        items.sort_by_key(|(_, modified)| *modified);
        items.reverse();
        items.dedup_by(|(left, _), (right, _)| left == right);
        if items.len() > per_ext_cap {
            items.truncate(per_ext_cap);
        }
        indexed_files += items.len();
    }

    CandidateInventory {
        per_ext,
        indexed_files,
    }
}

fn indexed_ext_set() -> &'static HashSet<String> {
    static INDEXED_SET: OnceLock<HashSet<String>> = OnceLock::new();
    INDEXED_SET.get_or_init(|| {
        INDEXED_CANDIDATE_EXTS
            .iter()
            .map(|ext| ext.to_string())
            .collect()
    })
}

fn candidate_inventory_key(ctx: &ScanContext) -> String {
    let mut roots = ctx
        .scan_roots
        .iter()
        .map(|p| p.to_string_lossy().to_lowercase())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();

    format!(
        "{}|depth={}|lookback={}|size={}|roots={}",
        ctx.profile.as_str(),
        ctx.profile.max_walk_depth(),
        ctx.profile.lookback_days(),
        ctx.profile.max_file_size_bytes(),
        roots.join(";")
    )
}

pub fn prefetch_dir() -> PathBuf {
    PathBuf::from(r"C:\Windows\Prefetch")
}

pub fn prefetch_file_names_by_prefixes(prefixes: &[&str]) -> Vec<String> {
    let names = cached_prefetch_names();
    let mut out = Vec::new();
    for name in names {
        let upper = name.to_ascii_uppercase();
        if prefixes
            .iter()
            .any(|prefix| upper.starts_with(&prefix.to_ascii_uppercase()))
        {
            out.push(name);
        }
    }
    out
}

fn cached_prefetch_names() -> Vec<String> {
    if let Some(cached) = prefetch_name_cache()
        .lock()
        .ok()
        .and_then(|cache| cache.as_ref().cloned())
    {
        return cached;
    }

    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(prefetch_dir()) {
        for entry in entries.flatten() {
            if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                names.push(name.to_string());
            }
        }
    }

    names.sort();
    names.dedup();

    if let Ok(mut cache) = prefetch_name_cache().lock() {
        *cache = Some(names.clone());
    }

    names
}

pub fn read_file_head(path: &Path, bytes: usize) -> Option<Vec<u8>> {
    let data = fs::read(path).ok()?;
    Some(data.into_iter().take(bytes).collect())
}

pub fn read_file_all(path: &Path) -> Option<Vec<u8>> {
    fs::read(path).ok()
}

pub fn decode_looks_like_prefetch(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        let mapped = match ch {
            'а' | 'А' => 'a',
            'е' | 'Е' => 'e',
            'о' | 'О' => 'o',
            'р' | 'Р' => 'p',
            'с' | 'С' => 'c',
            'х' | 'Х' => 'x',
            'у' | 'У' => 'y',
            'к' | 'К' => 'k',
            'м' | 'М' => 'm',
            'т' | 'Т' => 't',
            'в' | 'В' => 'b',
            'н' | 'Н' => 'h',
            _ => ch.to_lowercase().next().unwrap_or(ch),
        };
        out.push(mapped.to_lowercase().next().unwrap_or(mapped));
    }
    out
}

pub fn is_maybe_prefetch_name(name: &str) -> bool {
    decode_looks_like_prefetch(name) == "prefetch"
}

pub fn get_file_attributes(path: &Path) -> Option<u32> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
    use windows::core::PCWSTR;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let attrs = unsafe { GetFileAttributesW(PCWSTR(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        None
    } else {
        Some(attrs)
    }
}

pub fn path_display(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub fn truncate_text(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    value.chars().take(max).collect::<String>() + "..."
}

fn event_log_state_cache() -> &'static Mutex<HashMap<String, EventLogState>> {
    static EVENT_LOG_STATE_CACHE: OnceLock<Mutex<HashMap<String, EventLogState>>> = OnceLock::new();
    EVENT_LOG_STATE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn command_cache() -> &'static Mutex<HashMap<String, String>> {
    static COMMAND_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    COMMAND_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn filtered_event_cache() -> &'static Mutex<HashMap<String, Vec<EventRecord>>> {
    static FILTERED_EVENT_CACHE: OnceLock<Mutex<HashMap<String, Vec<EventRecord>>>> =
        OnceLock::new();
    FILTERED_EVENT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn channel_event_cache() -> &'static Mutex<HashMap<String, ChannelEventCache>> {
    static CHANNEL_EVENT_CACHE: OnceLock<Mutex<HashMap<String, ChannelEventCache>>> =
        OnceLock::new();
    CHANNEL_EVENT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn candidate_inventory_cache() -> &'static Mutex<HashMap<String, CandidateInventory>> {
    static CANDIDATE_INVENTORY_CACHE: OnceLock<Mutex<HashMap<String, CandidateInventory>>> =
        OnceLock::new();
    CANDIDATE_INVENTORY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prefetch_name_cache() -> &'static Mutex<Option<Vec<String>>> {
    static PREFETCH_NAME_CACHE: OnceLock<Mutex<Option<Vec<String>>>> = OnceLock::new();
    PREFETCH_NAME_CACHE.get_or_init(|| Mutex::new(None))
}

pub fn reset_runtime_caches() {
    if let Ok(mut cache) = command_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = filtered_event_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = channel_event_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = event_log_state_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = usn_state_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = ntfs_metadata_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = candidate_inventory_cache().lock() {
        cache.clear();
    }
    if let Ok(mut cache) = prefetch_name_cache().lock() {
        *cache = None;
    }
}

pub fn prewarm_runtime_caches(ctx: &ScanContext) -> RuntimePrewarmStats {
    let event_warm_plan: Vec<(&str, usize)> = match ctx.profile {
        ScanProfile::Quick => vec![
            ("Security", 1800),
            ("Microsoft-Windows-Sysmon/Operational", 1600),
            ("Microsoft-Windows-PowerShell/Operational", 1400),
            ("System", 1000),
            ("Application", 1000),
        ],
        ScanProfile::Deep => vec![
            ("Security", 2400),
            ("Microsoft-Windows-Sysmon/Operational", 2200),
            ("Microsoft-Windows-PowerShell/Operational", 1800),
            ("System", 1400),
            ("Application", 1400),
        ],
    };

    for (channel, count) in &event_warm_plan {
        let _ = ensure_channel_event_cache(channel, *count);
    }

    let mut stats = RuntimePrewarmStats {
        event_channels_warmed: event_warm_plan.len(),
        candidate_exts_indexed: 0,
        candidate_files_indexed: 0,
    };

    let key = candidate_inventory_key(ctx);
    let mut cache = match candidate_inventory_cache().lock() {
        Ok(guard) => guard,
        Err(_) => return stats,
    };
    if !cache.contains_key(&key) {
        cache.insert(key.clone(), build_candidate_inventory(ctx));
    }
    if let Some(inv) = cache.get(&key) {
        stats.candidate_exts_indexed = inv.per_ext.len();
        stats.candidate_files_indexed = inv.indexed_files;
    }

    stats
}

fn list_windows_drive_roots() -> Vec<String> {
    let output = run_command("fsutil", &["fsinfo", "drives"]).unwrap_or_default();
    let drive_re = Regex::new(r"(?i)\b([A-Z]:)\\").unwrap();
    let mut drives = Vec::new();

    for cap in drive_re.captures_iter(&output) {
        if let Some(m) = cap.get(1) {
            drives.push(m.as_str().to_ascii_uppercase());
        }
    }

    drives.sort();
    drives.dedup();

    if drives.is_empty() {
        vec!["C:".to_string()]
    } else {
        drives
    }
}

fn query_usn_journal_state_for_volume(volume: &str) -> UsnJournalState {
    if let Some(cached) = usn_state_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(volume).cloned())
    {
        return cached;
    }

    let output = run_command("fsutil", &["usn", "queryjournal", volume]).unwrap_or_default();
    let lower = output.to_lowercase();
    let access_denied = lower.contains("access is denied") || lower.contains("доступ запрещен");
    let missing = is_usn_journal_missing_output(&lower);
    let available = !access_denied && !missing && is_usn_journal_available_output(&output);

    let state = UsnJournalState {
        volume: volume.to_string(),
        available,
        missing,
        access_denied,
    };

    if let Ok(mut cache) = usn_state_cache().lock() {
        if cache.len() > 64 {
            cache.clear();
        }
        cache.insert(volume.to_string(), state.clone());
    }

    state
}

fn query_ntfs_volume_metadata_for_volume(volume: &str) -> NtfsVolumeMetadata {
    if let Some(cached) = ntfs_metadata_cache()
        .lock()
        .ok()
        .and_then(|m| m.get(volume).cloned())
    {
        return cached;
    }

    let output = run_command("fsutil", &["fsinfo", "ntfsinfo", volume]).unwrap_or_default();
    let lower = output.to_lowercase();

    let metadata = if output.trim().is_empty() {
        NtfsVolumeMetadata {
            volume: volume.to_string(),
            ntfs_version: None,
            lfs_version: None,
            mft_valid_data_length: None,
            mft_start_lcn: None,
            mft_mirror_start_lcn: None,
            bytes_per_file_record_segment: None,
            error: Some("empty fsutil ntfsinfo output".to_string()),
        }
    } else if lower.contains("not ntfs")
        || lower.contains("file system is raw")
        || lower.contains("the media is write protected")
    {
        NtfsVolumeMetadata {
            volume: volume.to_string(),
            ntfs_version: None,
            lfs_version: None,
            mft_valid_data_length: None,
            mft_start_lcn: None,
            mft_mirror_start_lcn: None,
            bytes_per_file_record_segment: None,
            error: Some("volume is not readable as NTFS".to_string()),
        }
    } else {
        NtfsVolumeMetadata {
            volume: volume.to_string(),
            ntfs_version: extract_ntfs_version(&output),
            lfs_version: extract_lfs_version(&output),
            mft_valid_data_length: extract_fsutil_value(&output, "Mft Valid Data Length").or_else(
                || extract_fsutil_value_contains(&output, &["mft", "valid", "data", "length"], &[]),
            ),
            mft_start_lcn: extract_mft_start_lcn(&output),
            mft_mirror_start_lcn: extract_mft_mirror_start_lcn(&output),
            bytes_per_file_record_segment: extract_fsutil_value(
                &output,
                "Bytes Per FileRecord Segment",
            )
            .or_else(|| {
                extract_fsutil_value_contains(&output, &["bytes", "filerecord", "segment"], &[])
            })
            .or_else(|| extract_fsutil_value_contains(&output, &["frs"], &[])),
            error: None,
        }
    };

    if let Ok(mut cache) = ntfs_metadata_cache().lock() {
        if cache.len() > 64 {
            cache.clear();
        }
        cache.insert(volume.to_string(), metadata.clone());
    }

    metadata
}

fn is_usn_journal_missing_output(output_lower: &str) -> bool {
    let normalized = output_lower.to_lowercase();
    normalized.contains("the usn journal is not active")
        || normalized.contains("usn journal is not active")
        || normalized.contains("there is no usn journal")
        || normalized.contains("cannot query usn journal")
        || normalized.contains("usn journal not found")
        || normalized.contains("не актив")
        || normalized.contains("журнал usn не найден")
        || normalized.contains("usn-журнал не найден")
}

fn is_usn_journal_available_output(output: &str) -> bool {
    let lower = output.to_lowercase();
    if lower.trim().is_empty() {
        return false;
    }

    if lower.contains("usn journal id")
        || lower.contains("next usn")
        || lower.contains("write range tracking")
    {
        return true;
    }

    // Localized output may still contain USN and multiple hex fields.
    let usn_mentions = lower.matches("usn").count();
    let hex_count = Regex::new(r"0x[0-9a-f]{4,}")
        .ok()
        .map(|re| re.find_iter(&lower).count())
        .unwrap_or(0);

    usn_mentions >= 2 && hex_count >= 3
}

fn usn_state_cache() -> &'static Mutex<HashMap<String, UsnJournalState>> {
    static USN_STATE_CACHE: OnceLock<Mutex<HashMap<String, UsnJournalState>>> = OnceLock::new();
    USN_STATE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ntfs_metadata_cache() -> &'static Mutex<HashMap<String, NtfsVolumeMetadata>> {
    static NTFS_METADATA_CACHE: OnceLock<Mutex<HashMap<String, NtfsVolumeMetadata>>> =
        OnceLock::new();
    NTFS_METADATA_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn extract_fsutil_value(output: &str, key_prefix: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed
            .to_lowercase()
            .starts_with(&key_prefix.to_lowercase())
        {
            continue;
        }
        let (_, rhs) = trimmed.split_once(':')?;
        let value = rhs.trim();
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

fn extract_fsutil_value_contains(
    output: &str,
    must_contain: &[&str],
    exclude: &[&str],
) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.contains(':') {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if must_contain.iter().any(|needle| !lower.contains(needle)) {
            continue;
        }
        if exclude.iter().any(|needle| lower.contains(needle)) {
            continue;
        }

        let (_, rhs) = trimmed.split_once(':')?;
        let value = rhs.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn extract_ntfs_version(output: &str) -> Option<String> {
    extract_fsutil_value(output, "NTFS Version").or_else(|| {
        Regex::new(r"(?i)\bntfs\b[^\d]{0,32}(\d+\.\d+)")
            .ok()
            .and_then(|re| {
                re.captures(output)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            })
    })
}

fn extract_lfs_version(output: &str) -> Option<String> {
    extract_fsutil_value(output, "LFS Version").or_else(|| {
        Regex::new(r"(?i)\blfs\b[^\d]{0,32}(\d+\.\d+)")
            .ok()
            .and_then(|re| {
                re.captures(output)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
            })
    })
}

fn extract_mft_start_lcn(output: &str) -> Option<String> {
    extract_fsutil_value(output, "Mft Start Lcn")
        .or_else(|| extract_fsutil_value_contains(output, &["mft", "lcn"], &["mft2", "mirr"]))
}

fn extract_mft_mirror_start_lcn(output: &str) -> Option<String> {
    extract_fsutil_value(output, "Mft2 Start Lcn")
        .or_else(|| extract_fsutil_value_contains(output, &["mft2", "lcn"], &[]))
        .or_else(|| extract_fsutil_value_contains(output, &["mftmirr", "lcn"], &[]))
}

fn parse_event_log_state_json(raw_json: &str) -> Option<EventLogState> {
    let value: Value = serde_json::from_str(raw_json.trim()).ok()?;

    let log_name = value
        .get("LogName")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let record_count = value.get("RecordCount").and_then(as_u64_from_json);
    let oldest_record_number = value.get("OldestRecordNumber").and_then(as_u64_from_json);
    let file_size_bytes = value.get("FileSize").and_then(as_u64_from_json);
    let is_enabled = value.get("IsEnabled").and_then(as_bool_from_json);
    let log_mode = value
        .get("LogMode")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty());
    let log_file_path = value
        .get("LogFilePath")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty());
    let last_write_time_utc = value
        .get("LastWriteTimeUtc")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty());
    let last_access_time_utc = value
        .get("LastAccessTimeUtc")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty());
    let error = value
        .get("Error")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .filter(|s| !s.is_empty());

    Some(EventLogState {
        log_name,
        record_count,
        oldest_record_number,
        file_size_bytes,
        is_enabled,
        log_mode,
        log_file_path,
        last_write_time_utc,
        last_access_time_utc,
        error,
    })
}

fn as_u64_from_json(value: &Value) -> Option<u64> {
    if let Some(v) = value.as_u64() {
        return Some(v);
    }
    value
        .as_i64()
        .and_then(|v| if v >= 0 { Some(v as u64) } else { None })
}

fn as_bool_from_json(value: &Value) -> Option<bool> {
    if let Some(v) = value.as_bool() {
        return Some(v);
    }
    let text = value.as_str()?.trim().to_lowercase();
    match text.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_looks_like_prefetch, extract_event_data_value, extract_fsutil_value,
        extract_xml_tag_value, is_maybe_prefetch_name, is_usn_journal_available_output,
        is_usn_journal_missing_output, parse_event_log_state_json, parse_event_records,
    };

    #[test]
    fn confusable_prefetch_name_detected() {
        assert!(is_maybe_prefetch_name("Prеfetch"));
        assert_eq!(decode_looks_like_prefetch("Prеfetch"), "prefetch");
    }

    #[test]
    fn parse_event_records_works() {
        let xml = r#"
<Event><System><Provider Name='X'/><EventID>1102</EventID><TimeCreated SystemTime='2026-01-01T00:00:00.0000000Z'/></System><EventData><Data>Security log was cleared</Data></EventData></Event>
"#;
        let parsed = parse_event_records(xml);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event_id, 1102);
        assert_eq!(parsed[0].provider, "X");
    }

    #[test]
    fn extract_event_data_value_by_name() {
        let xml = r#"<EventData><Data Name="SubjectUserName">alice</Data></EventData>"#;
        assert_eq!(
            extract_event_data_value(xml, "SubjectUserName").as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn extract_xml_tag_value_simple() {
        let xml = r#"<EventData><SubjectUserSid>S-1-5-18</SubjectUserSid></EventData>"#;
        assert_eq!(
            extract_xml_tag_value(xml, "SubjectUserSid").as_deref(),
            Some("S-1-5-18")
        );
    }

    #[test]
    fn parse_event_log_state_json_valid() {
        let json = r#"{
            "LogName":"Security",
            "RecordCount":1234,
            "OldestRecordNumber":12,
            "FileSize":4096,
            "IsEnabled":true,
            "LogMode":"Circular",
            "LogFilePath":"%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx",
            "LastWriteTimeUtc":"2026-01-01T00:00:00.0000000Z",
            "LastAccessTimeUtc":"2026-01-01T00:10:00.0000000Z",
            "Error":null
        }"#;
        let state = parse_event_log_state_json(json).expect("state must parse");
        assert_eq!(state.log_name, "Security");
        assert_eq!(state.record_count, Some(1234));
        assert_eq!(state.is_enabled, Some(true));
        assert!(state.error.is_none());
    }

    #[test]
    fn detect_missing_usn_journal_output() {
        assert!(is_usn_journal_missing_output(
            "Error: The USN journal is not active on this volume."
        ));
        assert!(!is_usn_journal_missing_output(
            "USN Journal ID : 0x01dc9542d73094f2"
        ));
    }

    #[test]
    fn detect_available_usn_journal_output() {
        let sample = "Usn Journal ID : 0x01dc9542d73094f2\nFirst Usn : 0x00000000a6000000\nNext Usn : 0x00000000a83325d8";
        assert!(is_usn_journal_available_output(sample));
    }

    #[test]
    fn extract_fsutil_value_parses_key() {
        let sample = "NTFS Version      :                3.1\nMft2 Start Lcn :                   0x0000000000000002";
        assert_eq!(
            extract_fsutil_value(sample, "NTFS Version").as_deref(),
            Some("3.1")
        );
        assert_eq!(
            extract_fsutil_value(sample, "Mft2 Start Lcn").as_deref(),
            Some("0x0000000000000002")
        );
    }
}
