use std::ffi::{CStr, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Result, anyhow};

#[link(name = "ss_native", kind = "static")]
unsafe extern "C" {
    fn ss_detect_vm(buffer: *mut i8, length: u64) -> i32;
    fn ss_verify_signature(path: *const u16) -> i32;
}

pub fn detect_vm() -> Result<Option<String>> {
    let mut buffer = vec![0i8; 512];
    let detected = unsafe { ss_detect_vm(buffer.as_mut_ptr(), buffer.len() as u64) };
    let brand = unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .trim()
        .to_string();

    match detected {
        0 => Ok(None),
        1 => Ok(Some(if brand.is_empty() {
            "Unknown VM".to_string()
        } else {
            brand
        })),
        other => Err(anyhow!(
            "native VM bridge returned unexpected status {other}"
        )),
    }
}

pub fn verify_signature(path: &Path) -> Result<bool> {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    match unsafe { ss_verify_signature(wide.as_ptr()) } {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(anyhow!(
            "native signature bridge returned unexpected status {other}"
        )),
    }
}
