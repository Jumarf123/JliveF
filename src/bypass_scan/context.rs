use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW};
use windows::core::PCWSTR;

use crate::bypass_scan::activity::collect_recent_activity_paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Quick,
    Deep,
}

impl ScanProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanProfile::Quick => "quick",
            ScanProfile::Deep => "deep",
        }
    }

    pub fn from_menu_choice(choice: &str) -> Option<Self> {
        match choice.trim() {
            "1" => Some(ScanProfile::Quick),
            "2" => Some(ScanProfile::Deep),
            _ => None,
        }
    }

    pub fn max_file_candidates(self) -> usize {
        match self {
            ScanProfile::Quick => 320,
            ScanProfile::Deep => 6000,
        }
    }

    pub fn max_file_size_bytes(self) -> u64 {
        match self {
            ScanProfile::Quick => 64 * 1024 * 1024,
            ScanProfile::Deep => 160 * 1024 * 1024,
        }
    }

    pub fn max_walk_depth(self) -> usize {
        match self {
            ScanProfile::Quick => 4,
            ScanProfile::Deep => 8,
        }
    }

    pub fn lookback_days(self) -> i64 {
        match self {
            ScanProfile::Quick => 14,
            ScanProfile::Deep => 365,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub profile: ScanProfile,
    pub scan_roots: Vec<PathBuf>,
    pub activity_paths: Vec<PathBuf>,
    pub report_dir: PathBuf,
    pub started_at_utc: String,
}

impl ScanContext {
    pub fn new(profile: ScanProfile, custom_root: Option<PathBuf>) -> Self {
        let mut roots = Vec::new();
        if let Some(root) = custom_root {
            roots.push(root);
        } else {
            roots.extend(default_scan_roots(profile));
        }

        roots.sort();
        roots.dedup();
        roots = prune_redundant_roots(roots);

        let activity_paths = if profile == ScanProfile::Quick {
            collect_recent_activity_paths(500)
        } else {
            Vec::new()
        };

        let report_dir = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("reports");

        Self {
            profile,
            scan_roots: roots,
            activity_paths,
            report_dir,
            started_at_utc: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn prune_redundant_roots(mut roots: Vec<PathBuf>) -> Vec<PathBuf> {
    roots.sort_by(|a, b| {
        let ac = a.components().count();
        let bc = b.components().count();
        ac.cmp(&bc)
            .then_with(|| a.to_string_lossy().cmp(&b.to_string_lossy()))
    });

    let mut out: Vec<PathBuf> = Vec::new();
    for root in roots {
        let redundant = out.iter().any(|existing| root.starts_with(existing));
        if !redundant {
            out.push(root);
        }
    }

    out
}

fn default_scan_roots(profile: ScanProfile) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if profile == ScanProfile::Deep {
        roots.extend(fixed_drive_roots());
    }

    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        let base = PathBuf::from(user_profile);
        roots.push(base.join("Desktop"));
        roots.push(base.join("Downloads"));
        roots.push(base.join("Documents"));
        roots.push(base.join("AppData\\Local\\Temp"));
        roots.push(base.join("AppData\\Roaming"));
    }

    if let Ok(temp) = std::env::var("TEMP") {
        roots.push(PathBuf::from(temp));
    }

    roots.into_iter().filter(|p| p.exists()).collect()
}

fn fixed_drive_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    let required = unsafe { GetLogicalDriveStringsW(None) } as usize;
    if required > 0 {
        let mut buf = vec![0u16; required + 1];
        let len = unsafe { GetLogicalDriveStringsW(Some(&mut buf)) } as usize;
        if len > 0 && len <= buf.len() {
            let mut start = 0usize;
            for i in 0..=len {
                if i == len || buf[i] == 0 {
                    if i > start {
                        let drive = String::from_utf16_lossy(&buf[start..i]);
                        let mut wide: Vec<u16> = OsStr::new(&drive).encode_wide().collect();
                        wide.push(0);
                        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
                        // DRIVE_FIXED == 3
                        if drive_type == 3 {
                            roots.push(PathBuf::from(&drive));
                        }
                    }
                    start = i + 1;
                }
            }
        }
    }

    if roots.is_empty() {
        for letter in 'C'..='Z' {
            let root = PathBuf::from(format!("{letter}:\\"));
            if root.exists() {
                roots.push(root);
            }
        }
    }

    roots
}
