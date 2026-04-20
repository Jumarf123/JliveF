use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::Result;

use crate::core::native;

static CACHE: OnceLock<Mutex<HashMap<PathBuf, bool>>> = OnceLock::new();

pub fn is_trusted(path: &Path) -> Result<bool> {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(value) = cache
        .lock()
        .expect("signature cache poisoned")
        .get(path)
        .copied()
    {
        return Ok(value);
    }

    let trusted = native::verify_signature(path)?;

    cache
        .lock()
        .expect("signature cache poisoned")
        .insert(path.to_path_buf(), trusted);

    Ok(trusted)
}
