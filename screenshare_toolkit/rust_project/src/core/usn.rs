use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1, USN_JOURNAL_DATA_V1,
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_COMPRESSION_CHANGE, USN_REASON_DATA_EXTEND,
    USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_TRUNCATION, USN_REASON_DESIRED_STORAGE_CLASS_CHANGE,
    USN_REASON_EA_CHANGE, USN_REASON_ENCRYPTION_CHANGE, USN_REASON_FILE_CREATE,
    USN_REASON_FILE_DELETE, USN_REASON_HARD_LINK_CHANGE, USN_REASON_INDEXABLE_CHANGE,
    USN_REASON_INTEGRITY_CHANGE, USN_REASON_NAMED_DATA_EXTEND, USN_REASON_NAMED_DATA_OVERWRITE,
    USN_REASON_NAMED_DATA_TRUNCATION, USN_REASON_OBJECT_ID_CHANGE, USN_REASON_RENAME_NEW_NAME,
    USN_REASON_RENAME_OLD_NAME, USN_REASON_REPARSE_POINT_CHANGE, USN_REASON_SECURITY_CHANGE,
    USN_REASON_STREAM_CHANGE, USN_REASON_TRANSACTED_CHANGE, USN_RECORD_COMMON_HEADER,
    USN_RECORD_UNION,
};
use windows::core::PCWSTR;

const BUFFER_SIZE: usize = 32 * 1024 * 1024;
const SCAN_BUDGET: Duration = Duration::from_secs(30);

const RELEVANT_REASON_MASK: u32 = USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_OVERWRITE
    | USN_REASON_NAMED_DATA_EXTEND
    | USN_REASON_NAMED_DATA_TRUNCATION
    | USN_REASON_FILE_CREATE
    | USN_REASON_FILE_DELETE
    | USN_REASON_RENAME_OLD_NAME
    | USN_REASON_RENAME_NEW_NAME
    | USN_REASON_BASIC_INFO_CHANGE
    | USN_REASON_INDEXABLE_CHANGE
    | USN_REASON_EA_CHANGE
    | USN_REASON_SECURITY_CHANGE
    | USN_REASON_HARD_LINK_CHANGE
    | USN_REASON_COMPRESSION_CHANGE
    | USN_REASON_ENCRYPTION_CHANGE
    | USN_REASON_OBJECT_ID_CHANGE
    | USN_REASON_REPARSE_POINT_CHANGE
    | USN_REASON_STREAM_CHANGE
    | USN_REASON_TRANSACTED_CHANGE
    | USN_REASON_INTEGRITY_CHANGE
    | USN_REASON_DESIRED_STORAGE_CLASS_CHANGE;

#[derive(Clone, Debug)]
pub struct UsnRecord {
    pub file_name: String,
    pub timestamp_raw: i64,
    pub reason: u32,
    pub usn: i64,
    pub file_reference: FileReference,
    pub parent_reference: FileReference,
}

#[derive(Clone, Copy, Debug)]
pub enum FileReference {
    V2(u64),
    V3([u8; 16]),
}

#[derive(Clone, Debug)]
pub struct UsnScan {
    pub records: Vec<UsnRecord>,
    pub timed_out: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct UsnScanSummary {
    pub timed_out: bool,
    pub processed: u64,
}

pub fn scan_volume(device: &str) -> Result<UsnScan> {
    let mut records = Vec::new();
    let summary = scan_volume_stream(device, |record| {
        records.push(record);
        Ok(())
    })?;

    Ok(UsnScan {
        records,
        timed_out: summary.timed_out,
    })
}

pub fn scan_volume_stream(
    device: &str,
    mut visitor: impl FnMut(UsnRecord) -> Result<()>,
) -> Result<UsnScanSummary> {
    let handle = open_volume(device)?;
    let result = scan_volume_handle(handle, &mut visitor);
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.with_context(|| format!("failed to scan USN journal on {device}"))
}

fn open_volume(device: &str) -> Result<HANDLE> {
    let trimmed = device.trim_end_matches('\\');
    let path = format!(r"\\.\{}", trimmed.trim_end_matches(':'));
    let path = format!("{path}:");
    let wide = to_wide(&path);

    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("failed to open volume {path}"))
}

fn scan_volume_handle(
    handle: HANDLE,
    visitor: &mut impl FnMut(UsnRecord) -> Result<()>,
) -> Result<UsnScanSummary> {
    let journal = query_journal(handle)?;
    let mut read = READ_USN_JOURNAL_DATA_V1 {
        StartUsn: journal.FirstUsn,
        ReasonMask: RELEVANT_REASON_MASK,
        ReturnOnlyOnClose: 0,
        Timeout: 0,
        BytesToWaitFor: 0,
        UsnJournalID: journal.UsnJournalID,
        MinMajorVersion: 2,
        MaxMajorVersion: journal.MaxSupportedMajorVersion.min(3),
    };

    let started = Instant::now();
    let mut processed = 0u64;
    let mut buffer = vec![0u8; BUFFER_SIZE];

    while read.StartUsn < journal.NextUsn {
        if started.elapsed() >= SCAN_BUDGET {
            return Ok(UsnScanSummary {
                timed_out: true,
                processed,
            });
        }

        let mut bytes_returned = 0u32;
        unsafe {
            DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                Some(&read as *const _ as *const _),
                size_of::<READ_USN_JOURNAL_DATA_V1>() as u32,
                Some(buffer.as_mut_ptr() as *mut _),
                buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            )?;
        }

        if bytes_returned <= size_of::<i64>() as u32 {
            break;
        }

        let next_usn = i64::from_le_bytes(buffer[0..8].try_into().expect("next usn length"));
        if next_usn <= read.StartUsn {
            break;
        }

        processed += parse_records(&buffer[..bytes_returned as usize], visitor)?;
        read.StartUsn = next_usn;
    }

    Ok(UsnScanSummary {
        timed_out: false,
        processed,
    })
}

fn query_journal(handle: HANDLE) -> Result<USN_JOURNAL_DATA_V1> {
    let mut journal = USN_JOURNAL_DATA_V1::default();
    let mut bytes_returned = 0u32;
    unsafe {
        DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut journal as *mut _ as *mut _),
            size_of::<USN_JOURNAL_DATA_V1>() as u32,
            Some(&mut bytes_returned),
            None,
        )?;
    }
    Ok(journal)
}

fn parse_records(buffer: &[u8], visitor: &mut impl FnMut(UsnRecord) -> Result<()>) -> Result<u64> {
    let mut offset = size_of::<i64>();
    let mut processed = 0u64;
    while offset + size_of::<USN_RECORD_COMMON_HEADER>() <= buffer.len() {
        let record_ptr = unsafe { buffer.as_ptr().add(offset) as *const USN_RECORD_UNION };
        let header = unsafe { (*record_ptr).Header };
        if header.RecordLength == 0 || offset + header.RecordLength as usize > buffer.len() {
            break;
        }

        let parsed = match header.MajorVersion {
            2 => parse_v2(buffer, offset, record_ptr),
            3 => parse_v3(buffer, offset, record_ptr),
            _ => None,
        };
        if let Some(record) = parsed {
            visitor(record)?;
            processed += 1;
        }

        offset += header.RecordLength as usize;
    }

    Ok(processed)
}

fn parse_v2(
    buffer: &[u8],
    offset: usize,
    record_ptr: *const USN_RECORD_UNION,
) -> Option<UsnRecord> {
    let record = unsafe { (*record_ptr).V2 };
    let name = read_record_name(buffer, offset, record.FileNameOffset, record.FileNameLength)?;
    Some(UsnRecord {
        file_name: name,
        timestamp_raw: record.TimeStamp,
        reason: record.Reason,
        usn: record.Usn,
        file_reference: FileReference::V2(record.FileReferenceNumber),
        parent_reference: FileReference::V2(record.ParentFileReferenceNumber),
    })
}

fn parse_v3(
    buffer: &[u8],
    offset: usize,
    record_ptr: *const USN_RECORD_UNION,
) -> Option<UsnRecord> {
    let record = unsafe { (*record_ptr).V3 };
    let name = read_record_name(buffer, offset, record.FileNameOffset, record.FileNameLength)?;
    Some(UsnRecord {
        file_name: name,
        timestamp_raw: record.TimeStamp,
        reason: record.Reason,
        usn: record.Usn,
        file_reference: FileReference::V3(record.FileReferenceNumber.Identifier),
        parent_reference: FileReference::V3(record.ParentFileReferenceNumber.Identifier),
    })
}

fn read_record_name(
    buffer: &[u8],
    record_offset: usize,
    name_offset: u16,
    name_length: u16,
) -> Option<String> {
    let start = record_offset + name_offset as usize;
    let end = start + name_length as usize;
    if end > buffer.len() || name_length == 0 {
        return None;
    }

    let units = buffer[start..end]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Some(OsString::from_wide(&units).to_string_lossy().into_owned())
}

pub fn filetime_i64_to_local(value: i64) -> chrono::DateTime<chrono::Local> {
    let raw = value as u64;
    crate::core::time::filetime_to_local(FILETIME {
        dwLowDateTime: raw as u32,
        dwHighDateTime: (raw >> 32) as u32,
    })
}

pub fn format_file_reference(value: FileReference) -> String {
    match value {
        FileReference::V2(id) => format!("{id:016X}"),
        FileReference::V3(id) => id
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(""),
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
