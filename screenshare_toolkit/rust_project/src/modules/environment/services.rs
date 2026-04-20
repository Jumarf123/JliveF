use anyhow::Result;
use chrono::Duration;
use serde::Deserialize;

use crate::core::paths::boot_time_local;
use crate::core::report::ModuleReport;
use crate::core::shell::run_powershell_json_array;
use crate::core::time::{format_datetime, parse_powershell_datetime};

#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct ServiceProcess {
    Name: Option<String>,
    ProcessId: Option<u32>,
    State: Option<String>,
    StartTime: Option<String>,
}

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let boot_time = boot_time_local() + Duration::seconds(120);
    let service_names = ["PlugPlay", "PcaSvc", "Schedule", "Eventlog", "DiagTrack"];

    for service_name in service_names {
        let services: Vec<ServiceProcess> = run_powershell_json_array(&format!(
            "$service = Get-CimInstance Win32_Service -Filter \"Name='{}'\" -ErrorAction SilentlyContinue; \
             if ($null -ne $service) {{ \
                $proc = Get-CimInstance Win32_Process -Filter \"ProcessId=$($service.ProcessId)\" -ErrorAction SilentlyContinue; \
                $startTime = $null; \
                if ($proc -and $proc.CreationDate) {{ \
                    try {{ \
                        $startTime = $proc.CreationDate.ToString('o') \
                    }} catch {{ \
                        $startTime = $null \
                    }} \
                }} \
                [pscustomobject]@{{ \
                    Name = $service.Name; \
                    ProcessId = $service.ProcessId; \
                    State = $service.State; \
                    StartTime = $startTime \
                }} \
             }}",
            service_name
        ))?;

        if let Some(service) = services.first() {
            if let Some(start_time) = service
                .StartTime
                .as_deref()
                .and_then(parse_powershell_datetime)
            {
                if start_time > boot_time {
                    report.add_warning(
                        format!("Service {service_name} restarted after boot"),
                        format!(
                            "ProcessId={}, State={}, StartTime={}",
                            service.ProcessId.unwrap_or_default(),
                            service.State.clone().unwrap_or_default(),
                            format_datetime(&start_time)
                        ),
                    );
                } else {
                    report.add_info(
                        format!("Service {service_name} is within the expected boot window"),
                        format!(
                            "ProcessId={}, State={}, StartTime={}",
                            service.ProcessId.unwrap_or_default(),
                            service.State.clone().unwrap_or_default(),
                            format_datetime(&start_time)
                        ),
                    );
                }
            } else if service_name != "DiagTrack" {
                report.add_warning(
                    format!("Service {service_name} did not expose a start time"),
                    "The service exists, but its process creation time could not be resolved."
                        .to_string(),
                );
            }
        } else if service_name != "DiagTrack" {
            report.add_warning(
                format!("Service {service_name} was not found"),
                "The expected service instance was not available during this check.",
            );
        }
    }

    Ok(())
}
