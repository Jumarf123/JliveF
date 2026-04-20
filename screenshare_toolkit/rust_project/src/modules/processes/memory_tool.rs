use anyhow::Result;
use serde::Deserialize;

use crate::core::memory;
use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Clone)]
pub struct ProcessInfo {
    pub Name: Option<String>,
    pub ProcessId: Option<u32>,
    pub ExecutablePath: Option<String>,
}

#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct ServiceInfo {
    ProcessId: Option<u32>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Clone)]
pub struct StartedProcess {
    pub Name: Option<String>,
    pub Id: Option<u32>,
    pub StartTime: Option<String>,
}

pub fn report_availability(report: &mut ModuleReport) {
    report.add_info(
        "Memory scanner ready",
        "Memory-backed checks run inside this executable.",
    );
}

pub fn scan_pid(pid: u32) -> Result<String> {
    match memory::dump_process_strings(pid) {
        Ok(strings) => Ok(strings.join("\n")),
        Err(error) if error.to_string().contains("0x80070005") => Ok(String::new()),
        Err(error) => Err(error),
    }
}

pub fn scan_pid_lines(pid: u32, visitor: impl FnMut(&str) -> Result<()>) -> Result<()> {
    match memory::visit_process_strings(pid, visitor) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("0x80070005") => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn get_processes_by_names(names: &[&str]) -> Result<Vec<ProcessInfo>> {
    let candidates = names
        .iter()
        .map(|name| format!("'{}'", name.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");

    run_powershell_json_array(&format!(
        "$targets = @({candidates}); \
         Get-CimInstance Win32_Process | \
         Where-Object {{ $targets -contains $_.Name }} | \
         Select-Object Name, ProcessId, ExecutablePath"
    ))
}

pub fn get_started_processes(names: &[&str]) -> Result<Vec<StartedProcess>> {
    let base_names = names
        .iter()
        .map(|name| name.trim_end_matches(".exe"))
        .map(|name| format!("'{}'", name.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");

    run_powershell_json_array(&format!(
        "$targets = @({base_names}); \
         Get-Process -ErrorAction SilentlyContinue | \
         Where-Object {{ $targets -contains $_.Name }} | \
         Select-Object Name, Id, @{{
             Name = 'StartTime'; Expression = {{ try {{ $_.StartTime.ToString('o') }} catch {{ $null }} }}
         }}"
    ))
}

pub fn get_service_pid(service_name: &str) -> Result<Option<u32>> {
    let services: Vec<ServiceInfo> = run_powershell_json_array(&format!(
        "Get-CimInstance Win32_Service -Filter \"Name='{}'\" | Select-Object ProcessId",
        service_name.replace('\'', "''")
    ))?;

    Ok(services.first().and_then(|service| service.ProcessId))
}
