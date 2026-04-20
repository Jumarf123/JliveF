use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub fn write_utf8_bom(path: &Path, content: &str) -> Result<()> {
    let mut bytes = Vec::with_capacity(3 + content.len());
    bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    bytes.extend_from_slice(content.as_bytes());
    fs::write(path, bytes).with_context(|| format!("failed to write text file: {}", path.display()))
}
