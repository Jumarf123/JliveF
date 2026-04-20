use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use regex::Regex;

use crate::core::report::ModuleReport;
use crate::core::signatures::is_trusted;
use crate::core::usn;
use windows::Win32::System::Ioctl::{USN_REASON_FILE_DELETE, USN_REASON_RENAME_OLD_NAME};

pub fn run(report: &mut ModuleReport) -> Result<()> {
    println!();
    println!("[csrss] Two string-dump files are required.");
    println!("[csrss] 1) Dump the csrss.exe instance with the most private bytes.");
    println!("[csrss] 2) Dump the csrss.exe instance with the least private bytes.");
    println!("[csrss] Press Enter or type `cancel` to skip this step.");

    let first = prompt_for_path("Path to the first dump file: ")?;
    let Some(first) = first else {
        report.add_info(
            "csrss dump check skipped",
            "The operator cancelled the dump step.",
        );
        return Ok(());
    };

    let second = prompt_for_path("Path to the second dump file: ")?;
    let Some(second) = second else {
        report.add_info(
            "csrss dump check stopped",
            "The second dump path was not provided.",
        );
        return Ok(());
    };

    let journal_lines = load_deleted_journal_lines()?;
    analyze_first_dump(report, &first, &journal_lines)?;
    analyze_second_dump(report, &second, &journal_lines)?;

    report.add_info(
        "csrss dump parsing completed",
        "Both dump files were processed.",
    );
    Ok(())
}

fn prompt_for_path(prompt: &str) -> Result<Option<PathBuf>> {
    loop {
        print!("{prompt}");
        io::stdout().flush()?;
        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            return Ok(None);
        }
        let trimmed = input.trim();

        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("cancel") {
            return Ok(None);
        }

        if matches!(trimmed, "0" | "1" | "2" | "3") {
            return Ok(None);
        }

        let path = PathBuf::from(trimmed);
        if path.is_file() {
            return Ok(Some(path));
        }

        println!("The file was not found. Enter a valid path or `cancel`.");
    }
}

fn load_deleted_journal_lines() -> Result<HashSet<String>> {
    let scan = usn::scan_volume("C:")?;
    Ok(scan
        .records
        .into_iter()
        .filter(|record| record.reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME) != 0)
        .map(|record| record.file_name.to_ascii_lowercase())
        .collect())
}

fn analyze_first_dump(
    report: &mut ModuleReport,
    path: &PathBuf,
    deleted_lines: &HashSet<String>,
) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let regex_modified_extension = Regex::new(r"^[A-Za-z]:\\.*\..*")?;
    let regex_dll = Regex::new(r"^[A-Za-z]:\\.+?\.dll")?;
    let regex_without_ext1 = Regex::new(r"^[A-Za-z]:\\(?:[^.\\]+\\)*[^.\\]+$")?;
    let regex_without_ext2 = Regex::new(r"^\\\\\?\\(?:[^.\\]+\\)*[^.\\]+$")?;

    let mut printed = HashSet::new();

    for line in content.lines() {
        if line.len() > 400 {
            continue;
        }
        let Some((_, matched)) = line.split_once(':') else {
            continue;
        };
        let matched = matched.trim();
        if matched.is_empty() || !printed.insert(matched.to_string()) {
            continue;
        }

        if regex_modified_extension.is_match(matched) && is_modified_extension_candidate(matched) {
            report_path_status(
                report,
                "csrss modified extension",
                matched,
                deleted_lines,
                true,
            )?;
            continue;
        }

        if regex_dll.is_match(matched) {
            report_path_status(
                report,
                "csrss dll injection trace",
                matched,
                deleted_lines,
                false,
            )?;
            continue;
        }

        if regex_without_ext1.is_match(matched) || regex_without_ext2.is_match(matched) {
            let path = PathBuf::from(matched);
            if path.is_dir() {
                continue;
            }

            if path.exists() {
                report.add_warning(
                    "csrss file without extension",
                    format!("Executed file without extension: {}", path.display()),
                );
            } else if is_journal_deleted(matched, deleted_lines) {
                report.add_warning(
                    "csrss deleted file without extension",
                    format!("Executed & deleted file without extension: {matched}"),
                );
            }
        }
    }

    Ok(())
}

fn analyze_second_dump(
    report: &mut ModuleReport,
    path: &PathBuf,
    deleted_lines: &HashSet<String>,
) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let regex_exe = Regex::new(r"^[A-Za-z]:\\.+?\.exe")?;
    let mut printed = HashSet::new();

    for line in content.lines() {
        if line.len() > 400 {
            continue;
        }
        let Some((_, matched)) = line.split_once(':') else {
            continue;
        };
        let matched = matched.trim();
        if matched.is_empty()
            || !regex_exe.is_match(matched)
            || !printed.insert(matched.to_string())
        {
            continue;
        }

        report_path_status(report, "csrss executed file", matched, deleted_lines, false)?;
    }

    Ok(())
}

fn report_path_status(
    report: &mut ModuleReport,
    label: &str,
    matched: &str,
    deleted_lines: &HashSet<String>,
    check_pe_like: bool,
) -> Result<()> {
    let path = PathBuf::from(matched);
    if path.exists() {
        let should_check_signature = if check_pe_like {
            true
        } else {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll"))
                .unwrap_or(false)
        };

        if should_check_signature && !is_trusted(&path)? {
            report.add_warning(
                label,
                format!("Executed & unsigned file: {}", path.display()),
            );
        }
    } else if is_journal_deleted(matched, deleted_lines)
        || !matched.to_ascii_lowercase().starts_with("c:\\")
    {
        report.add_warning(label, format!("Executed & deleted file: {matched}"));
    }

    Ok(())
}

fn is_journal_deleted(path: &str, deleted_lines: &HashSet<String>) -> bool {
    let lowered = path.trim().to_ascii_lowercase();
    let file_name = PathBuf::from(path)
        .file_name()
        .map(|value| value.to_string_lossy().to_ascii_lowercase());
    deleted_lines
        .iter()
        .any(|line| line.contains(&lowered) || file_name.as_ref().is_some_and(|name| line == name))
}

fn is_modified_extension_candidate(path: &str) -> bool {
    let lowered = path.trim().to_ascii_lowercase();
    !lowered.ends_with(".exe")
        && !lowered.ends_with(".dll")
        && !lowered.ends_with('\\')
        && !lowered.ends_with(".exe.config")
        && !lowered
            .rfind(".dll.")
            .is_some_and(|index| lowered[index..].ends_with(".config"))
}
