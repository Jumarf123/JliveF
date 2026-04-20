use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::thread;

use anyhow::Result;
use serde::Deserialize;

use crate::core::parsers::contains_non_ascii;
use crate::core::paths::{boot_time_local, module_results_dir};
use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;
use crate::core::text::write_utf8_bom;
use crate::core::time::{format_datetime, parse_powershell_datetime};
use crate::core::usn::{self, UsnRecord};
use windows::Win32::System::Ioctl::{USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Clone)]
struct DiskEntry {
    DeviceID: Option<String>,
    FileSystem: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct StreamInfo {
    FullName: Option<String>,
    LastWriteTime: Option<String>,
}

struct DriveExport {
    device: String,
    rename_old: Vec<String>,
    rename_new: Vec<String>,
    created_files: Vec<PathBuf>,
    access_denied: bool,
    timed_out: bool,
    processed: u64,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    scan_journal_cleared(report)?;
    export_filtered_journal(report)?;
    Ok(())
}

fn scan_journal_cleared(report: &mut ModuleReport) -> Result<()> {
    let boot_time = boot_time_local();
    let disks: Vec<DiskEntry> = run_powershell_json_array(
        "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, FileSystem",
    )?;

    for disk in disks {
        let Some(device) = disk.DeviceID else {
            continue;
        };
        let stream_path = format!("{device}\\$Extend\\$UsnJrnl:$J");
        let info: Vec<StreamInfo> = run_powershell_json_array(&format!(
            "Get-Item -LiteralPath '{}' -ErrorAction SilentlyContinue | \
             Select-Object FullName, @{{
                Name='LastWriteTime'; Expression={{ $_.LastWriteTime.ToString('o') }}
             }}",
            stream_path.replace('\'', "''")
        ))?;

        if let Some(item) = info.first()
            && let Some(last_write) = item
                .LastWriteTime
                .as_deref()
                .and_then(parse_powershell_datetime)
            && last_write > boot_time
        {
            report.add_warning(
                format!("USN journal modified after boot on {device}"),
                format!(
                    "{} at {}",
                    item.FullName.clone().unwrap_or(stream_path.clone()),
                    format_datetime(&last_write)
                ),
            );
        }
    }

    Ok(())
}

fn export_filtered_journal(report: &mut ModuleReport) -> Result<()> {
    let export_root = module_results_dir(2, "Disk and Journal Forensics")?.join("usn");
    if export_root.exists() {
        fs::remove_dir_all(&export_root)?;
    }
    fs::create_dir_all(&export_root)?;

    let disks: Vec<DiskEntry> = run_powershell_json_array(
        "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, FileSystem",
    )?;
    let ntfs_drives = disks
        .into_iter()
        .filter(|disk| disk.FileSystem.as_deref() == Some("NTFS"))
        .filter_map(|disk| disk.DeviceID)
        .collect::<Vec<_>>();

    let mut handles = Vec::new();
    for device in ntfs_drives {
        let export_root = export_root.clone();
        handles.push(thread::spawn(move || export_drive(device, export_root)));
    }

    let mut aggregated_old = Vec::new();
    let mut aggregated_new = Vec::new();
    let mut created_paths = Vec::new();
    let mut denied_drives = Vec::new();
    let mut timed_out_drives = Vec::new();
    let mut processed_records = 0u64;

    for handle in handles {
        let drive = handle
            .join()
            .map_err(|_| anyhow::anyhow!("USN worker panicked"))??;
        aggregated_old.extend(drive.rename_old);
        aggregated_new.extend(drive.rename_new);
        created_paths.extend(drive.created_files);
        if drive.access_denied {
            denied_drives.push(drive.device.clone());
        }
        if drive.timed_out {
            timed_out_drives.push(drive.device.clone());
        }
        processed_records += drive.processed;
    }

    let replaced = compare_renamed_files(&aggregated_old, &aggregated_new);
    if !replaced.is_empty() {
        let replaced_path = export_root.join("replaced_files.txt");
        write_utf8_bom(&replaced_path, &replaced.join("\n"))?;
        report.add_warning(
            "Potentially replaced files detected",
            format!("{} rename pairs detected.", replaced.len()),
        );
    }

    let manifest_path = export_root.join("usn_manifest.txt");
    let manifest = build_manifest(&created_paths, &denied_drives);
    write_utf8_bom(&manifest_path, &manifest)?;
    created_paths.push(manifest_path);

    if !denied_drives.is_empty() {
        report.add_critical(
            "USN journal access denied",
            format!(
                "Run the executable as administrator to read the journal on: {}",
                denied_drives.join(", ")
            ),
        );
    }
    if !timed_out_drives.is_empty() {
        report.add_critical(
            "USN scan budget reached",
            format!(
                "The native journal reader stopped after 30 seconds on: {}",
                timed_out_drives.join(", ")
            ),
        );
    }

    report.add_info("USN records scanned", processed_records.to_string());
    Ok(())
}

fn export_drive(device: String, export_root: PathBuf) -> Result<DriveExport> {
    let mut buckets = JournalBuckets::default();
    let scan = match usn::scan_volume_stream(&device, |record| {
        buckets.ingest(&device, record);
        Ok(())
    }) {
        Ok(scan) => scan,
        Err(error)
            if error.to_string().contains("Access is denied")
                || error.to_string().contains("failed to open volume") =>
        {
            return Ok(DriveExport {
                device,
                rename_old: Vec::new(),
                rename_new: Vec::new(),
                created_files: Vec::new(),
                access_denied: true,
                timed_out: false,
                processed: 0,
            });
        }
        Err(error) => return Err(error),
    };

    finish_drive_export(device, export_root, buckets, scan.timed_out, scan.processed)
}

#[derive(Default)]
struct JournalBuckets {
    buckets: BTreeMap<&'static str, Vec<String>>,
}

impl JournalBuckets {
    fn ingest(&mut self, device: &str, record: UsnRecord) {
        let lowered = record.file_name.to_ascii_lowercase();
        let mut formatted = None::<String>;

        if record.reason & USN_REASON_RENAME_OLD_NAME != 0 {
            self.push(
                "rename_old",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if record.reason & USN_REASON_RENAME_NEW_NAME != 0 {
            self.push(
                "rename_new",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if contains_non_ascii(&record.file_name) || record.file_name.contains('?') {
            self.push(
                "special_characters",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if lowered.contains(".mcf") {
            self.push(
                "glorious",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if lowered.contains("settings.db") {
            self.push(
                "logitech",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if lowered.contains(".amc2") {
            self.push(
                "bloody",
                cached_record_line(device, &record, &mut formatted),
            );
        }
        if lowered.contains(".cuecfg") {
            self.push(
                "corsair",
                cached_record_line(device, &record, &mut formatted),
            );
        }
    }

    fn push(&mut self, bucket: &'static str, line: String) {
        self.buckets.entry(bucket).or_default().push(line);
    }
}

fn cached_record_line(device: &str, record: &UsnRecord, cached: &mut Option<String>) -> String {
    if cached.is_none() {
        *cached = Some(format_record(device, record));
    }
    cached.as_ref().expect("record line cached").clone()
}

fn finish_drive_export(
    device: String,
    export_root: PathBuf,
    buckets: JournalBuckets,
    timed_out: bool,
    processed: u64,
) -> Result<DriveExport> {
    let rename_old = buckets
        .buckets
        .get("rename_old")
        .cloned()
        .unwrap_or_default();
    let rename_new = buckets
        .buckets
        .get("rename_new")
        .cloned()
        .unwrap_or_default();
    let mut created_files = Vec::new();

    for (bucket, lines) in buckets.buckets {
        if lines.is_empty() {
            continue;
        }
        let file_name = format!(
            "{}_{}.txt",
            device.replace(':', "").to_ascii_lowercase(),
            bucket
        );
        let destination = export_root.join(file_name);
        write_utf8_bom(&destination, &lines.join("\n"))?;
        created_files.push(destination);
    }

    if timed_out {
        let destination = export_root.join(format!(
            "{}_scan_budget_reached.txt",
            device.replace(':', "").to_ascii_lowercase()
        ));
        write_utf8_bom(
            &destination,
            "The native USN scan reached the 30 second safety budget before the journal ended.",
        )?;
        created_files.push(destination);
    }

    Ok(DriveExport {
        device,
        rename_old,
        rename_new,
        created_files,
        access_denied: false,
        timed_out,
        processed,
    })
}

fn format_record(device: &str, record: &UsnRecord) -> String {
    format!(
        "{},{:08X},{},{},{},{},{}",
        device,
        record.reason,
        format_datetime(&usn::filetime_i64_to_local(record.timestamp_raw)),
        sanitize_csv(&record.file_name),
        record.usn,
        usn::format_file_reference(record.file_reference),
        usn::format_file_reference(record.parent_reference)
    )
}

fn sanitize_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn compare_renamed_files(old_lines: &[String], new_lines: &[String]) -> Vec<String> {
    let old_entries = old_lines.iter().filter_map(|line| parse_rename_entry(line));
    let new_entries: Vec<(String, String)> = new_lines
        .iter()
        .filter_map(|line| parse_rename_entry(line))
        .collect();

    let mut result = Vec::new();
    for entry in old_entries {
        if new_entries.iter().any(|candidate| candidate == &entry) {
            result.push(format!("{}, {}", entry.0, entry.1));
        }
    }

    result.sort();
    result.dedup();
    result
}

fn parse_rename_entry(line: &str) -> Option<(String, String)> {
    let columns = split_csv_line(line);
    if columns.len() < 4 {
        return None;
    }

    let timestamp = columns.get(2)?.trim().trim_matches('"').to_string();
    let file_name = columns.get(3)?.trim().trim_matches('"').to_string();

    if file_name.is_empty() || timestamp.is_empty() {
        return None;
    }

    Some((file_name, timestamp))
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                result.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        result.push(current.trim().to_string());
    }

    result
}

fn build_manifest(created_paths: &[PathBuf], denied_drives: &[String]) -> String {
    let mut lines = vec!["USN export manifest".to_string(), String::new()];

    if created_paths.is_empty() {
        lines.push("Created files: none".to_string());
    } else {
        lines.push("Created files:".to_string());
        for path in created_paths {
            lines.push(path.display().to_string());
        }
    }

    lines.push(String::new());
    if denied_drives.is_empty() {
        lines.push("Journal access: ok".to_string());
    } else {
        lines.push(format!(
            "Journal access denied on: {}",
            denied_drives.join(", ")
        ));
    }

    lines.join("\n")
}
