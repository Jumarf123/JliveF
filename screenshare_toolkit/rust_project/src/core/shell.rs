use std::ffi::OsString;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn run_command_capture(program: &str, args: &[OsString]) -> Result<String> {
    crate::core::console::configure();
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to start command: {program}"))?;
    crate::core::console::configure();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = stderr.if_empty(&stdout).if_empty("<empty stdout/stderr>");
        bail!("{program} failed: {detail}");
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn run_powershell(script: &str) -> Result<String> {
    let args = vec![
        OsString::from("-NoProfile"),
        OsString::from("-ExecutionPolicy"),
        OsString::from("Bypass"),
        OsString::from("-Command"),
        OsString::from(format!(
            "$ErrorActionPreference='Stop'; \
             [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); \
             $OutputEncoding = [Console]::OutputEncoding; \
             {script}"
        )),
    ];

    run_command_capture("powershell", &args)
}

pub fn run_powershell_json<T: DeserializeOwned>(script: &str) -> Result<T> {
    let json = run_powershell(&format!(
        "& {{ {script} }} | ConvertTo-Json -Compress -Depth 8"
    ))?;
    serde_json::from_str(json.trim())
        .with_context(|| format!("failed to deserialize PowerShell JSON for script: {script}"))
}

pub fn run_powershell_json_array<T: DeserializeOwned>(script: &str) -> Result<Vec<T>> {
    let json = run_powershell(&format!(
        "& {{ {script} }} | ConvertTo-Json -Compress -Depth 8"
    ))?;
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(json.trim()).with_context(|| {
        format!("failed to deserialize PowerShell JSON array for script: {script}")
    })?;
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<T>, _>>()
            .context("failed to deserialize PowerShell JSON array"),
        other => Ok(vec![serde_json::from_value(other)?]),
    }
}

pub fn quote_ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

trait EmptyFallback {
    fn if_empty(self, fallback: &str) -> String;
}

impl EmptyFallback for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}
