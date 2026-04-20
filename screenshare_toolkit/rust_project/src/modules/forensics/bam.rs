use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use anyhow::Result;
use serde::Deserialize;

use crate::core::paths::{
    boot_time_local, convert_device_path_to_dos_with_map, dos_device_map, module_results_dir,
};
use crate::core::report::ModuleReport;
use crate::core::shell::{run_powershell, run_powershell_json_array};
use crate::core::signatures::is_trusted;
use crate::core::text::write_utf8_bom;
use crate::core::time::{format_date, format_datetime, parse_powershell_datetime};
use crate::core::yara_rules;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Clone)]
struct BamEntry {
    Path: Option<String>,
    Time: Option<String>,
    UserKey: Option<String>,
}

#[derive(Clone)]
struct PreparedBamEntry {
    timestamp: chrono::DateTime<chrono::Local>,
    user_key: String,
    resolved: Option<PathBuf>,
    display_path: String,
    name: String,
    exists: bool,
    size: u64,
}

#[derive(Clone)]
struct PathAnalysis {
    yara_rule: String,
    trusted: bool,
}

struct BamRow {
    timestamp: chrono::DateTime<chrono::Local>,
    date: String,
    name: String,
    path: String,
    deleted: String,
    rule: String,
}

struct BamWarning {
    title: String,
    detail: String,
}

struct BamOutcome {
    row: BamRow,
    warnings: Vec<BamWarning>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let threshold = get_last_interactive_logon()?.unwrap_or_else(boot_time_local);
    let export_dir = module_results_dir(2, "Disk and Journal Forensics")?.join("bam");
    fs::create_dir_all(&export_dir)?;
    let export_path = export_dir.join("BAM.txt");

    let entries: Vec<BamEntry> = run_powershell_json_array(
        "$result = @(); \
         $items = Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings' -ErrorAction SilentlyContinue; \
         foreach ($item in $items) { \
            foreach ($name in $item.GetValueNames()) { \
                $raw = $item.GetValue($name); \
                if ($name -like '\\Device\\*' -and $raw -is [byte[]] -and $raw.Length -ge 8) { \
                    $ft = [BitConverter]::ToInt64($raw, 0); \
                    $result += [pscustomobject]@{ \
                        Path = $name; \
                        Time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime().ToString('o'); \
                        UserKey = $item.PSChildName \
                    }; \
                } \
            } \
         }; \
         $result",
    )?;

    let device_map = dos_device_map();
    let trace = std::env::var("RUST_PROJECT_TRACE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let prepared_entries = prepare_entries(entries, &device_map);
    let analyses = analyze_unique_paths(&prepared_entries, trace)?;
    let outcomes = build_outcomes(prepared_entries, threshold, &analyses);

    let mut rows = Vec::new();
    for outcome in outcomes {
        rows.push(outcome.row);
        for warning in outcome.warnings {
            report.add_warning(warning.title, warning.detail);
        }
    }

    rows.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.path.cmp(&right.path))
    });
    write_utf8_bom(&export_path, &render_table(&rows))?;
    Ok(())
}

fn prepare_entries(
    entries: Vec<BamEntry>,
    device_map: &[(String, String)],
) -> Vec<PreparedBamEntry> {
    let mut prepared = Vec::new();

    for entry in entries {
        let Some(raw_path) = entry.Path.as_deref() else {
            continue;
        };
        let Some(timestamp) = entry.Time.as_deref().and_then(parse_powershell_datetime) else {
            continue;
        };

        let resolved = convert_device_path_to_dos_with_map(raw_path, device_map);
        let display_path = resolved
            .as_ref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| raw_path.to_string());
        let name = executable_name(resolved.as_deref().unwrap_or_else(|| Path::new(raw_path)));
        let exists = resolved.as_ref().is_some_and(|path| path.exists());
        let size = resolved
            .as_ref()
            .filter(|path| path.exists())
            .and_then(|path| fs::metadata(path).ok())
            .map(|meta| meta.len())
            .unwrap_or_default();

        prepared.push(PreparedBamEntry {
            timestamp,
            user_key: entry.UserKey.unwrap_or_default(),
            resolved,
            display_path,
            name,
            exists,
            size,
        });
    }

    prepared
}

fn analyze_unique_paths(
    entries: &[PreparedBamEntry],
    trace: bool,
) -> Result<HashMap<PathBuf, PathAnalysis>> {
    let current_exe = std::env::current_exe().ok();
    let mut seen = HashSet::new();
    let mut unique_paths = Vec::new();

    for entry in entries {
        let Some(path) = entry.resolved.as_ref() else {
            continue;
        };
        if !entry.exists || !seen.insert(path.clone()) {
            continue;
        }
        unique_paths.push((path.clone(), entry.size));
    }

    if unique_paths.is_empty() {
        return Ok(HashMap::new());
    }

    unique_paths.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));

    let worker_count = thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .clamp(1, 16)
        .min(unique_paths.len());
    let mut buckets = vec![Vec::new(); worker_count];
    for (index, item) in unique_paths.into_iter().enumerate() {
        buckets[index % worker_count].push(item);
    }

    let mut handles = Vec::new();
    for bucket in buckets {
        let current_exe = current_exe.clone();
        handles.push(thread::spawn(
            move || -> Result<Vec<(PathBuf, PathAnalysis)>> {
                bucket
                    .into_iter()
                    .map(|(path, size)| analyze_path(path, size, trace, current_exe.as_deref()))
                    .collect()
            },
        ));
    }

    let mut analyses = HashMap::new();
    for handle in handles {
        for (path, analysis) in handle
            .join()
            .map_err(|_| anyhow::anyhow!("BAM path-analysis worker panicked"))??
        {
            analyses.insert(path, analysis);
        }
    }

    Ok(analyses)
}

fn analyze_path(
    path: PathBuf,
    size: u64,
    trace: bool,
    current_exe: Option<&Path>,
) -> Result<(PathBuf, PathAnalysis)> {
    let yara_started = Instant::now();
    let rules = if current_exe.is_some_and(|current| same_file_path(current, &path)) {
        Vec::new()
    } else {
        yara_rules::scan_file(&path)?
    };
    if trace {
        let elapsed = yara_started.elapsed().as_secs_f64();
        if elapsed >= 0.05 {
            eprintln!(
                "[trace] module2 BAM YARA-X {:.2}s size={} path={}",
                elapsed,
                size,
                path.display()
            );
        }
    }

    let signature_started = Instant::now();
    let trusted = is_trusted(&path)?;
    if trace {
        let elapsed = signature_started.elapsed().as_secs_f64();
        if elapsed >= 0.05 {
            eprintln!(
                "[trace] module2 BAM signature {:.2}s path={}",
                elapsed,
                path.display()
            );
        }
    }

    Ok((
        path,
        PathAnalysis {
            yara_rule: if rules.is_empty() {
                "-".to_string()
            } else {
                rules.join(", ")
            },
            trusted,
        },
    ))
}

fn same_file_path(left: &Path, right: &Path) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

fn normalize_path_for_compare(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .trim_start_matches(r"\\?\")
        .to_ascii_lowercase()
}

fn build_outcomes(
    entries: Vec<PreparedBamEntry>,
    threshold: chrono::DateTime<chrono::Local>,
    analyses: &HashMap<PathBuf, PathAnalysis>,
) -> Vec<BamOutcome> {
    let mut outcomes = Vec::new();

    for entry in entries {
        let analysis = entry
            .resolved
            .as_ref()
            .and_then(|path| analyses.get(path))
            .cloned();
        let deleted = if entry.resolved.is_some() {
            if entry.exists { "No" } else { "Yes" }
        } else {
            "Unknown"
        }
        .to_string();
        let rule = analysis
            .as_ref()
            .map(|item| item.yara_rule.clone())
            .unwrap_or_else(|| "-".to_string());
        let row = BamRow {
            timestamp: entry.timestamp,
            date: format_date(&entry.timestamp),
            name: entry.name.clone(),
            path: entry.display_path.clone(),
            deleted: deleted.clone(),
            rule: rule.clone(),
        };

        let mut warnings = Vec::new();
        if entry.timestamp > threshold {
            if let (Some(path), Some(analysis)) = (entry.resolved.as_ref(), analysis.as_ref())
                && entry.exists
                && !analysis.trusted
            {
                warnings.push(BamWarning {
                    title: "BAM unsigned file".to_string(),
                    detail: format!(
                        "{} at {} (UserKey={})",
                        path.display(),
                        format_datetime(&entry.timestamp),
                        entry.user_key
                    ),
                });
            }

            if deleted == "Yes" {
                warnings.push(BamWarning {
                    title: "BAM deleted file".to_string(),
                    detail: format!(
                        "{} at {} (UserKey={})",
                        entry.display_path,
                        format_datetime(&entry.timestamp),
                        entry.user_key
                    ),
                });
            }

            if rule != "-" {
                warnings.push(BamWarning {
                    title: "BAM YARA match".to_string(),
                    detail: format!(
                        "{} matched rule `{}` at {}",
                        entry.display_path,
                        rule,
                        format_datetime(&entry.timestamp)
                    ),
                });
            }
        }

        outcomes.push(BamOutcome { row, warnings });
    }

    outcomes
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

fn executable_name(path: &Path) -> String {
    path.file_name()
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

fn render_table(rows: &[BamRow]) -> String {
    let date_width = column_width("Date", rows.iter().map(|row| row.date.as_str()));
    let name_width = column_width("Name", rows.iter().map(|row| row.name.as_str()));
    let path_width = column_width("Path", rows.iter().map(|row| row.path.as_str()));
    let deleted_width = column_width("Deleted", rows.iter().map(|row| row.deleted.as_str()));
    let rule_width = column_width("Rule", rows.iter().map(|row| row.rule.as_str()));

    let mut output = format!(
        "{:<date_width$} | {:<name_width$} | {:<path_width$} | {:<deleted_width$} | {:<rule_width$}\n",
        "Date", "Name", "Path", "Deleted", "Rule",
    );
    output.push_str(&format!(
        "{}-+-{}-+-{}-+-{}-+-{}\n",
        "-".repeat(date_width),
        "-".repeat(name_width),
        "-".repeat(path_width),
        "-".repeat(deleted_width),
        "-".repeat(rule_width),
    ));

    for row in rows {
        output.push_str(&format!(
            "{:<date_width$} | {:<name_width$} | {:<path_width$} | {:<deleted_width$} | {:<rule_width$}\n",
            row.date,
            sanitize_cell(&row.name),
            sanitize_cell(&row.path),
            row.deleted,
            sanitize_cell(&row.rule),
        ));
    }

    output
}

fn column_width<'a>(header: &str, values: impl Iterator<Item = &'a str>) -> usize {
    values
        .map(cell_len)
        .fold(cell_len(header), |width, value| width.max(value))
}

fn cell_len(value: &str) -> usize {
    value.chars().count()
}

fn sanitize_cell(value: &str) -> String {
    value.replace(['\r', '\n'], " ").replace('|', "/")
}
