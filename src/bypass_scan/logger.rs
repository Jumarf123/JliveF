use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::Serialize;
use serde_json::json;

#[derive(Clone)]
pub struct JsonLogger {
    file: Arc<Mutex<File>>,
    path: PathBuf,
}

impl JsonLogger {
    pub fn new(report_dir: &Path) -> Result<Self> {
        fs::create_dir_all(report_dir)?;
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let path = report_dir.join(format!("bypass_scan_log_{ts}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn info(&self, module: &str, message: &str) {
        self.log(module, "info", message, json!({}));
    }

    pub fn warn(&self, module: &str, message: &str) {
        self.log(module, "warn", message, json!({}));
    }

    pub fn error(&self, module: &str, message: &str) {
        self.log(module, "error", message, json!({}));
    }

    pub fn log<T: Serialize>(&self, module: &str, level: &str, message: &str, fields: T) {
        let mut guard = match self.file.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        let line = json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "level": level,
            "module": module,
            "message": message,
            "fields": fields,
        });

        if let Ok(text) = serde_json::to_string(&line) {
            let _ = guard.write_all(text.as_bytes());
            let _ = guard.write_all(b"\n");
        }
    }
}
