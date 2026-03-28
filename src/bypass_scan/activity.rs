use std::collections::HashSet;
use std::path::PathBuf;

use regex::Regex;

use crate::bypass_scan::utils::{query_event_records, run_powershell};

pub fn collect_recent_activity_paths(limit: usize) -> Vec<PathBuf> {
    let mut out = HashSet::new();

    collect_from_security_process_events(&mut out);
    collect_from_recent_links(&mut out, limit);
    collect_from_bam_and_runmru(&mut out, limit);

    let mut items = out.into_iter().filter(|p| p.is_file()).collect::<Vec<_>>();

    items.sort();
    if items.len() > limit {
        items.truncate(limit);
    }
    items
}

fn collect_from_security_process_events(set: &mut HashSet<PathBuf>) {
    let path_re = Regex::new(r#"(?i)<Data Name=['\"]NewProcessName['\"]>([^<]+)</Data>"#).unwrap();

    for ev in query_event_records("Security", &[4688], 500) {
        if let Some(path) = path_re
            .captures(&ev.raw_xml)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
            .and_then(|s| normalize_path_candidate(&s))
        {
            set.insert(path);
        }
    }
}

fn collect_from_recent_links(set: &mut HashSet<PathBuf>, limit: usize) {
    let take = limit.min(400);
    let script = format!(
        "$recent = Join-Path $env:APPDATA 'Microsoft\\Windows\\Recent'; if (!(Test-Path $recent)) {{ return }}; $w = New-Object -ComObject WScript.Shell; Get-ChildItem -LiteralPath $recent -Filter *.lnk -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First {take} | ForEach-Object {{ try {{ $t = $w.CreateShortcut($_.FullName).TargetPath; if ($t) {{ $t }} }} catch {{ }} }}"
    );

    if let Some(output) = run_powershell(&script) {
        for line in output.lines() {
            if let Some(path) = normalize_path_candidate(line) {
                set.insert(path);
            }
        }
    }
}

fn collect_from_bam_and_runmru(set: &mut HashSet<PathBuf>, limit: usize) {
    let take = limit.min(500);
    let script = format!(
        "$out = New-Object System.Collections.Generic.List[string];
$roots = @('HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings','HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings');
foreach ($r in $roots) {{
  if (Test-Path $r) {{
    Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue | ForEach-Object {{
      try {{
        $_.GetValueNames() | ForEach-Object {{ if ($_ -match '^[A-Za-z]:\\\\' -or $_ -match '^\\\\\\\\\\?\\\\') {{ $out.Add($_) }} }}
      }} catch {{ }}
    }}
  }}
}}
$mruPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU';
if (Test-Path $mruPath) {{
  try {{
    $p = Get-ItemProperty -LiteralPath $mruPath -ErrorAction Stop;
    $p.PSObject.Properties | ForEach-Object {{
      if ($_.Name -match '^[a-zA-Z]$' -and $_.Value) {{ $out.Add([string]$_.Value) }}
    }}
  }} catch {{ }}
}}
$out | Select-Object -Unique | Select-Object -First {take}"
    );

    if let Some(output) = run_powershell(&script) {
        for line in output.lines() {
            if let Some(path) = normalize_path_candidate(line) {
                set.insert(path);
            }
        }
    }
}

fn normalize_path_candidate(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_matches('"').trim_matches('`');
    if trimmed.is_empty() {
        return None;
    }

    let mut value = trimmed.to_string();

    if value.starts_with(r"\\?\") {
        value = value.trim_start_matches(r"\\?\").to_string();
    }

    if let Some(first) = value.split_whitespace().next() {
        value = first.to_string();
    }

    if !value.contains(':') {
        return None;
    }

    let bytes = value.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }

    Some(PathBuf::from(value))
}
