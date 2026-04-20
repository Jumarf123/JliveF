use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, TimeZone, Utc};
use windows::Win32::Foundation::FILETIME;

pub fn system_time_to_local(value: SystemTime) -> DateTime<Local> {
    DateTime::<Local>::from(value)
}

pub fn parse_powershell_datetime(value: &str) -> Option<DateTime<Local>> {
    if value.trim().is_empty() {
        return None;
    }

    chrono::DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Local))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .and_then(|naive| Local.from_local_datetime(&naive).single())
        })
}

pub fn format_datetime(value: &DateTime<Local>) -> String {
    value.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn format_date(value: &DateTime<Local>) -> String {
    value.format("%d.%m.%Y").to_string()
}

pub fn filetime_to_local(filetime: FILETIME) -> DateTime<Local> {
    let ticks = ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64;
    let seconds_since_windows_epoch = ticks / 10_000_000;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    let unix_seconds = seconds_since_windows_epoch.saturating_sub(11_644_473_600);
    let system_time = UNIX_EPOCH + Duration::new(unix_seconds, nanos);
    DateTime::<Utc>::from(system_time).with_timezone(&Local)
}
