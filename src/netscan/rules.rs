use crate::netscan::netsh;
use crate::netscan::registry::{
    ValueResult, enumerate_subkeys, open_hklm_subkey, read_string, read_text_like, read_u32_like,
    value_exists,
};
use crate::netscan::report::{Finding, Report};
use winreg::RegKey;

const HKLM_PREFIX: &str = "HKLM\\";
const INTERFACES_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
const TCP_GLOBAL_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
const CLASS_PATH: &str =
    "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
const AFD_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters";
const ENUM_PCI_PATH: &str = "SYSTEM\\CurrentControlSet\\Enum\\PCI";
const MULTIMEDIA_SYSTEM_PROFILE_PATH: &str =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile";
const NETWORK_CLASS_GUID: &str = "{4d36e972-e325-11ce-bfc1-08002be10318}";

pub fn run_all_scans() -> Report {
    let mut report = Report::new();
    scan_registry(&mut report);
    netsh::scan_netsh(&mut report);
    report
}

pub fn scan_registry(report: &mut Report) {
    scan_interfaces(report);
    scan_tcpip_parameters(report);
    scan_class_adapters(report);
    scan_pci_interrupts(report);
    scan_multimedia_system_profile(report);
    scan_afd(report);
}

fn scan_interfaces(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{INTERFACES_PATH}");
    let Ok(base) = open_hklm_subkey(INTERFACES_PATH) else {
        report.add_warning(Finding::new(
            "Interfaces",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    let subkeys = match enumerate_subkeys(&base) {
        Ok(keys) => keys,
        Err(err) => {
            report.add_warning(Finding::new(
                "Interfaces",
                full_path.clone(),
                String::new(),
                None,
                format!("Не удалось перечислить интерфейсы: {}", err),
            ));
            return;
        }
    };

    for iface in subkeys {
        let path = format!("{}\\{}", full_path, iface);
        let Ok(if_key) = base.open_subkey(&iface) else {
            report.add_warning(Finding::new(
                "Interfaces",
                path.clone(),
                String::new(),
                None,
                "Нет доступа к интерфейсу",
            ));
            continue;
        };

        let ip_info = match get_interface_ip(&if_key) {
            Ok(ip) => ip,
            Err(err) => {
                report.add_warning(Finding::new(
                    "Interfaces-IP",
                    path.clone(),
                    "IPAddress".to_string(),
                    None,
                    format!("Не удалось прочитать IP адрес интерфейса: {}", err),
                ));
                None
            }
        };

        report.inc_checked();
        match read_u32_like(&if_key, "MTU") {
            ValueResult::Value(v) if is_suspicious_mtu(v) => {
                let details = match ip_info {
                    Some(ref ip) if !ip.is_empty() => {
                        format!("Подозрительный MTU {} (IP {})", v, ip)
                    }
                    _ => format!("Подозрительный MTU {}", v),
                };
                report.add_violation(Finding::new(
                    "MTU",
                    path.clone(),
                    "MTU".to_string(),
                    Some(v.to_string()),
                    details,
                ));
            }
            ValueResult::Value(_) => {}
            ValueResult::Missing => {}
            ValueResult::NotReadable(err) => report.add_warning(Finding::new(
                "MTU",
                path.clone(),
                "MTU".to_string(),
                None,
                format!("Не удалось прочитать MTU: {}", err),
            )),
        }

        // MSS presence
        report.inc_checked();
        match value_exists(&if_key, "MSS") {
            Ok(true) => report.add_violation(Finding::new(
                "MSS",
                path.clone(),
                "MSS".to_string(),
                None,
                "Найден запрещённый ключ MSS (сам факт наличия)".to_string(),
            )),
            Ok(false) => {}
            Err(err) => report.add_warning(Finding::new(
                "MSS",
                path.clone(),
                "MSS".to_string(),
                None,
                format!("Не удалось проверить MSS: {}", err),
            )),
        }

        // RSS presence
        report.inc_checked();
        match value_exists(&if_key, "RSS") {
            Ok(true) => report.add_violation(Finding::new(
                "RSS",
                path.clone(),
                "RSS".to_string(),
                None,
                "Найден запрещённый ключ RSS (сам факт наличия)".to_string(),
            )),
            Ok(false) => {}
            Err(err) => report.add_warning(Finding::new(
                "RSS",
                path.clone(),
                "RSS".to_string(),
                None,
                format!("Не удалось проверить RSS: {}", err),
            )),
        }

        for key_name in ["TCPNoDelay", "TcpAckFrequency", "TcpDelAckTicks"] {
            report.inc_checked();
            match value_exists(&if_key, key_name) {
                Ok(true) => report.add_violation(Finding::new(
                    key_name,
                    path.clone(),
                    key_name.to_string(),
                    None,
                    "Найден запрещённый ключ (сам факт наличия)".to_string(),
                )),
                Ok(false) => {}
                Err(err) => report.add_warning(Finding::new(
                    key_name,
                    path.clone(),
                    key_name.to_string(),
                    None,
                    format!("Не удалось прочитать ключ: {}", err),
                )),
            }
        }
    }
}

fn get_interface_ip(key: &RegKey) -> Result<Option<String>, String> {
    fn normalize_ip_list(list: Vec<String>) -> Option<String> {
        list.into_iter()
            .find(|s| !s.trim().is_empty() && s.trim() != "0.0.0.0")
            .map(|s| s.trim().to_string())
    }

    // Prefer DhcpIPAddress, then IPAddress. Try string first, then multi-string.
    for name in ["DhcpIPAddress", "IPAddress"] {
        if let Ok(v) = key.get_value::<String, _>(name) {
            let t = v.trim();
            if !t.is_empty() && t != "0.0.0.0" {
                return Ok(Some(t.to_string()));
            }
        }
        match key.get_value::<Vec<String>, _>(name) {
            Ok(list) => {
                if let Some(ip) = normalize_ip_list(list) {
                    return Ok(Some(ip));
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.to_string());
                }
            }
        }
    }
    Ok(None)
}

fn scan_tcpip_parameters(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{TCP_GLOBAL_PATH}");
    let Ok(base) = open_hklm_subkey(TCP_GLOBAL_PATH) else {
        report.add_warning(Finding::new(
            "Tcpip\\Parameters",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    check_global_dword(report, &base, "GlobalMaxTcpWindowSize", |v| {
        if v < 60000 {
            Some(format!("{} < 60000", v))
        } else {
            None
        }
    });

    check_global_dword(report, &base, "SackOpts", |v| {
        if v == 0 {
            Some("SackOpts = 0 (должно быть включено)".to_string())
        } else {
            None
        }
    });

    check_global_dword(report, &base, "TcpMaxDataRetransmissions", |v| {
        if v > 6 {
            Some(format!("TcpMaxDataRetransmissions = {}, допустимо <=6", v))
        } else {
            None
        }
    });

    check_global_dword(report, &base, "EnablePMTUDiscovery", |v| {
        if v == 0 {
            Some("EnablePMTUDiscovery = 0 (должно быть включено)".to_string())
        } else {
            None
        }
    });

    check_global_dword(report, &base, "EnablePMTUBHDetect", |v| {
        if v == 0 {
            Some("EnablePMTUBHDetect = 0 (должно быть включено)".to_string())
        } else {
            None
        }
    });

    check_global_dword(report, &base, "Tcp1323Opts", |v| {
        if v == 0 || v == 1 {
            Some(format!(
                "Tcp1323Opts = {} (0 и 1 запрещены, нужно другое значение)",
                v
            ))
        } else {
            None
        }
    });

    check_global_dword(report, &base, "EnableWsd", |v| {
        if v == 0 {
            Some("EnableWsd = 0 (подозрительное закрепление TCP-тюнинга)".to_string())
        } else {
            None
        }
    });

    check_global_dword(report, &base, "DisableTaskOffload", |v| {
        if v == 1 {
            Some("DisableTaskOffload = 1 (полное отключение task offload)".to_string())
        } else {
            None
        }
    });
}

fn check_global_dword<F>(report: &mut Report, key: &winreg::RegKey, name: &str, validator: F)
where
    F: Fn(u32) -> Option<String>,
{
    let path = format!("{}{}", HKLM_PREFIX, TCP_GLOBAL_PATH);
    check_dword_at_path(report, key, &path, name, validator);
}

fn check_dword_at_path<F>(
    report: &mut Report,
    key: &winreg::RegKey,
    path: &str,
    name: &str,
    validator: F,
) where
    F: Fn(u32) -> Option<String>,
{
    report.inc_checked();
    match read_u32_like(key, name) {
        ValueResult::Missing => {}
        ValueResult::Value(v) => {
            if let Some(msg) = validator(v) {
                report.add_violation(Finding::new(
                    name,
                    path.to_string(),
                    name.to_string(),
                    Some(v.to_string()),
                    msg,
                ));
            }
        }
        ValueResult::NotReadable(err) => report.add_warning(Finding::new(
            name,
            path.to_string(),
            name.to_string(),
            None,
            format!("Не удалось прочитать значение: {}", err),
        )),
    }
}

fn scan_class_adapters(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{CLASS_PATH}");
    let Ok(base) = open_hklm_subkey(CLASS_PATH) else {
        report.add_warning(Finding::new(
            "ClassAdapters",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    let subkeys = match enumerate_subkeys(&base) {
        Ok(keys) => keys,
        Err(err) => {
            report.add_warning(Finding::new(
                "ClassAdapters",
                full_path.clone(),
                String::new(),
                None,
                format!("Не удалось перечислить адаптеры: {}", err),
            ));
            return;
        }
    };

    for sub in subkeys {
        if sub.len() != 4 || !sub.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let path = format!("{}\\{}", full_path, sub);
        let Ok(adapter_key) = base.open_subkey(&sub) else {
            report.add_warning(Finding::new(
                "ClassAdapters",
                path.clone(),
                String::new(),
                None,
                "Нет доступа к адаптеру",
            ));
            continue;
        };

        let driver_desc = match read_string(&adapter_key, "DriverDesc") {
            ValueResult::Value(v) => v,
            ValueResult::Missing => continue,
            ValueResult::NotReadable(err) => {
                report.add_warning(Finding::new(
                    "DriverDesc",
                    path.clone(),
                    "DriverDesc".to_string(),
                    None,
                    format!("Не удалось прочитать DriverDesc: {}", err),
                ));
                continue;
            }
        };

        let component_id = match read_text_like(&adapter_key, "ComponentId") {
            ValueResult::Value(v) if !v.is_empty() => Some(v),
            _ => None,
        };

        scan_adapter_enabled_warning_flag(
            report,
            &adapter_key,
            &path,
            &driver_desc,
            &["*InterruptModeration", "InterruptModeration"],
            "*InterruptModeration",
            "включена группировка прерываний (это не бан само по себе, а latency-risk настройка)",
        );
        scan_adapter_interrupt_rate(
            report,
            &adapter_key,
            &path,
            &driver_desc,
            &["*InterruptModerationRate", "InterruptModerationRate"],
            "*InterruptModerationRate",
        );
        scan_adapter_interrupt_rate(
            report,
            &adapter_key,
            &path,
            &driver_desc,
            &["RxIntModeration"],
            "RxIntModeration",
        );
        if !is_virtual_adapter(&driver_desc, component_id.as_deref()) {
            scan_adapter_u32_flag(
                report,
                &adapter_key,
                &path,
                &driver_desc,
                &["*NdisDeviceType", "NdisDeviceType"],
                "*NdisDeviceType",
                |value| {
                    if value == 1 {
                        Some("NdisDeviceType = 1".to_string())
                    } else {
                        None
                    }
                },
            );
        }
        scan_adapter_u32_flag(
            report,
            &adapter_key,
            &path,
            &driver_desc,
            &["*JumboPacket", "JumboPacket"],
            "*JumboPacket",
            |value| {
                if value != 0 && value != 1514 {
                    Some(format!(
                        "JumboPacket = {} (ожидается 1514 / disabled)",
                        value
                    ))
                } else {
                    None
                }
            },
        );

        if looks_like_wifi_adapter(&driver_desc, component_id.as_deref()) {
            scan_adapter_u32_flag(
                report,
                &adapter_key,
                &path,
                &driver_desc,
                &["ScanValidInterval"],
                "ScanValidInterval",
                |value| {
                    if value >= 120 {
                        Some(format!(
                            "ScanValidInterval = {} (Wi-Fi сканирование эфира замедлено)",
                            value
                        ))
                    } else {
                        None
                    }
                },
            );
        }
    }
}

fn scan_pci_interrupts(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{ENUM_PCI_PATH}");
    let Ok(base) = open_hklm_subkey(ENUM_PCI_PATH) else {
        report.add_warning(Finding::new(
            "Enum\\PCI",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    let devices = match enumerate_subkeys(&base) {
        Ok(keys) => keys,
        Err(err) => {
            report.add_warning(Finding::new(
                "Enum\\PCI",
                full_path.clone(),
                String::new(),
                None,
                format!("Не удалось перечислить PCI устройства: {}", err),
            ));
            return;
        }
    };

    for device in devices {
        let Ok(device_key) = base.open_subkey(&device) else {
            continue;
        };
        let instances = match enumerate_subkeys(&device_key) {
            Ok(keys) => keys,
            Err(_) => continue,
        };

        for instance in instances {
            let Ok(instance_key) = device_key.open_subkey(&instance) else {
                continue;
            };
            if !is_network_pci_instance(&instance_key) {
                continue;
            }

            let instance_path = format!("{}\\{}\\{}", full_path, device, instance);
            let label = pci_instance_label(&instance_key, &instance);
            let msi_rel_path = format!(
                "{}\\{}\\{}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties",
                ENUM_PCI_PATH, device, instance
            );
            let msi_path = format!("{HKLM_PREFIX}{msi_rel_path}");

            report.inc_checked();
            let Ok(msi_key) = open_hklm_subkey(&msi_rel_path) else {
                report.add_warning(Finding::new(
                    "MSISupported",
                    instance_path,
                    "MSISupported".to_string(),
                    None,
                    format!(
                        "Устройство: {}. Ветка MessageSignaledInterruptProperties отсутствует",
                        label
                    ),
                ));
                continue;
            };

            match read_u32_like(&msi_key, "MSISupported") {
                ValueResult::Value(1) => {}
                ValueResult::Value(v) => report.add_violation(Finding::new(
                    "MSISupported",
                    msi_path,
                    "MSISupported".to_string(),
                    Some(v.to_string()),
                    format!("Устройство: {}. Ожидается 1", label),
                )),
                ValueResult::Missing => report.add_warning(Finding::new(
                    "MSISupported",
                    msi_path,
                    "MSISupported".to_string(),
                    None,
                    format!("Устройство: {}. Значение отсутствует", label),
                )),
                ValueResult::NotReadable(err) => report.add_warning(Finding::new(
                    "MSISupported",
                    msi_path,
                    "MSISupported".to_string(),
                    None,
                    format!(
                        "Устройство: {}. Не удалось прочитать значение: {}",
                        label, err
                    ),
                )),
            }
        }
    }
}

fn scan_multimedia_system_profile(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{MULTIMEDIA_SYSTEM_PROFILE_PATH}");
    let Ok(base) = open_hklm_subkey(MULTIMEDIA_SYSTEM_PROFILE_PATH) else {
        report.add_warning(Finding::new(
            "SystemProfile",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    check_dword_at_path(report, &base, &full_path, "NetworkThrottlingIndex", |v| {
        if v != u32::MAX && v <= 9 {
            Some(format!(
                "NetworkThrottlingIndex = {} (троттлинг сетевых пакетов включён)",
                v
            ))
        } else {
            None
        }
    });

    check_dword_at_path(report, &base, &full_path, "SystemResponsiveness", |v| {
        if v == 100 {
            Some("SystemResponsiveness = 100".to_string())
        } else {
            None
        }
    });
}

fn scan_afd(report: &mut Report) {
    let full_path = format!("{HKLM_PREFIX}{AFD_PATH}");
    let Ok(base) = open_hklm_subkey(AFD_PATH) else {
        report.add_warning(Finding::new(
            "AFD",
            full_path.clone(),
            String::new(),
            None,
            "Нет доступа к ветке или она отсутствует",
        ));
        return;
    };

    report.inc_checked();
    match read_u32_like(&base, "FastSendDatagramThreshold") {
        ValueResult::Value(1500) => {}
        ValueResult::Value(v) if is_suspicious_fast_send_datagram_threshold(v) => report
            .add_violation(Finding::new(
                "FastSendDatagramThreshold",
                full_path.clone(),
                "FastSendDatagramThreshold".to_string(),
                Some(v.to_string()),
                format!("Подозрительное значение {}", v),
            )),
        ValueResult::Value(_) => {}
        ValueResult::Missing => {}
        ValueResult::NotReadable(err) => report.add_warning(Finding::new(
            "FastSendDatagramThreshold",
            full_path.clone(),
            "FastSendDatagramThreshold".to_string(),
            None,
            format!("Не удалось прочитать значение: {}", err),
        )),
    }
}

fn is_suspicious_mtu(value: u32) -> bool {
    (value >= 100 && value < 1_499) || value > 1_501
}

fn is_suspicious_fast_send_datagram_threshold(value: u32) -> bool {
    value != 0 && value != 1500 && (value < 512 || value > 65_535)
}

fn scan_adapter_enabled_warning_flag(
    report: &mut Report,
    adapter_key: &RegKey,
    path: &str,
    driver_desc: &str,
    key_names: &[&str],
    rule_name: &str,
    reason: &str,
) {
    report.inc_checked();
    let (used_key, result) = read_first_text_like(adapter_key, key_names);
    match result {
        ValueResult::Value(value) if looks_enabled(&value) => report.add_warning(Finding::new(
            rule_name,
            path.to_string(),
            used_key,
            Some(value.clone()),
            format!("Адаптер: {}. {}", driver_desc, reason),
        )),
        ValueResult::Value(_) | ValueResult::Missing => {}
        ValueResult::NotReadable(err) => report.add_warning(Finding::new(
            rule_name,
            path.to_string(),
            used_key,
            None,
            format!(
                "Адаптер: {}. Не удалось прочитать значение: {}",
                driver_desc, err
            ),
        )),
    }
}

fn scan_adapter_interrupt_rate(
    report: &mut Report,
    adapter_key: &RegKey,
    path: &str,
    driver_desc: &str,
    key_names: &[&str],
    rule_name: &str,
) {
    report.inc_checked();
    let (used_key, result) = read_first_text_like(adapter_key, key_names);
    match result {
        ValueResult::Value(value) if is_suspicious_interrupt_rate(&value) => {
            report.add_violation(Finding::new(
                rule_name,
                path.to_string(),
                used_key,
                Some(value.clone()),
                format!(
                    "Адаптер: {}. Подозрительная настройка interrupt moderation rate",
                    driver_desc
                ),
            ))
        }
        ValueResult::Value(_) | ValueResult::Missing => {}
        ValueResult::NotReadable(err) => report.add_warning(Finding::new(
            rule_name,
            path.to_string(),
            used_key,
            None,
            format!(
                "Адаптер: {}. Не удалось прочитать значение: {}",
                driver_desc, err
            ),
        )),
    }
}

fn scan_adapter_u32_flag<F>(
    report: &mut Report,
    adapter_key: &RegKey,
    path: &str,
    driver_desc: &str,
    key_names: &[&str],
    rule_name: &str,
    validator: F,
) where
    F: Fn(u32) -> Option<String>,
{
    report.inc_checked();
    let (used_key, result) = read_first_u32_like(adapter_key, key_names);
    match result {
        ValueResult::Value(value) => {
            if let Some(message) = validator(value) {
                report.add_violation(Finding::new(
                    rule_name,
                    path.to_string(),
                    used_key,
                    Some(value.to_string()),
                    format!("Адаптер: {}. {}", driver_desc, message),
                ));
            }
        }
        ValueResult::Missing => {}
        ValueResult::NotReadable(err) => report.add_warning(Finding::new(
            rule_name,
            path.to_string(),
            used_key,
            None,
            format!(
                "Адаптер: {}. Не удалось прочитать значение: {}",
                driver_desc, err
            ),
        )),
    }
}

fn read_first_u32_like(key: &RegKey, key_names: &[&str]) -> (String, ValueResult<u32>) {
    let mut last_error: Option<(String, String)> = None;
    for name in key_names {
        match read_u32_like(key, name) {
            ValueResult::Missing => continue,
            ValueResult::Value(value) => return ((*name).to_string(), ValueResult::Value(value)),
            ValueResult::NotReadable(err) => last_error = Some(((*name).to_string(), err)),
        }
    }

    if let Some((name, err)) = last_error {
        (name, ValueResult::NotReadable(err))
    } else {
        (
            key_names.first().copied().unwrap_or("").to_string(),
            ValueResult::Missing,
        )
    }
}

fn read_first_text_like(key: &RegKey, key_names: &[&str]) -> (String, ValueResult<String>) {
    let mut last_error: Option<(String, String)> = None;
    for name in key_names {
        match read_text_like(key, name) {
            ValueResult::Missing => continue,
            ValueResult::Value(value) => return ((*name).to_string(), ValueResult::Value(value)),
            ValueResult::NotReadable(err) => last_error = Some(((*name).to_string(), err)),
        }
    }

    if let Some((name, err)) = last_error {
        (name, ValueResult::NotReadable(err))
    } else {
        (
            key_names.first().copied().unwrap_or("").to_string(),
            ValueResult::Missing,
        )
    }
}

fn looks_enabled(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "1" | "enabled" | "enable" | "true" | "on" | "yes"
    ) || normalized.starts_with("enabled")
}

fn is_suspicious_interrupt_rate(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "1" | "3" | "low" | "extreme") || normalized.contains("extreme")
}

fn looks_like_wifi_adapter(driver_desc: &str, component_id: Option<&str>) -> bool {
    let desc = driver_desc.to_ascii_lowercase();
    if ["wireless", "wi-fi", "wifi", "wlan", "802.11"]
        .iter()
        .any(|needle| desc.contains(needle))
    {
        return true;
    }

    component_id
        .map(|id| {
            let lower = id.to_ascii_lowercase();
            lower.contains("wireless")
                || lower.contains("wifi")
                || lower.contains("wlan")
                || lower.contains("80211")
        })
        .unwrap_or(false)
}

fn is_virtual_adapter(driver_desc: &str, component_id: Option<&str>) -> bool {
    let desc = driver_desc.to_ascii_lowercase();
    if [
        "virtualbox",
        "host-only",
        "vmware",
        "hyper-v",
        "tap-",
        "tap ",
        "wintun",
        "npcap",
        "loopback",
        "vpn",
        "miniport",
        "virtual",
        "pseudo",
        "hamachi",
    ]
    .iter()
    .any(|needle| desc.contains(needle))
    {
        return true;
    }

    component_id
        .map(|id| {
            let lower = id.to_ascii_lowercase();
            [
                "virtual", "vbox", "vmware", "tap", "wintun", "vpn", "loopback", "miniport",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
        })
        .unwrap_or(false)
}

fn is_network_pci_instance(instance_key: &RegKey) -> bool {
    matches!(
        read_text_like(instance_key, "ClassGUID"),
        ValueResult::Value(ref guid) if guid.eq_ignore_ascii_case(NETWORK_CLASS_GUID)
    ) || matches!(
        read_text_like(instance_key, "Driver"),
        ValueResult::Value(ref driver)
            if driver.to_ascii_lowercase().contains(&NETWORK_CLASS_GUID.to_ascii_lowercase())
    )
}

fn pci_instance_label(instance_key: &RegKey, fallback: &str) -> String {
    for name in ["FriendlyName", "DeviceDesc", "DriverDesc"] {
        if let ValueResult::Value(value) = read_text_like(instance_key, name) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    fallback.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        is_suspicious_interrupt_rate, is_virtual_adapter, looks_enabled, looks_like_wifi_adapter,
    };

    #[test]
    fn interrupt_rate_detects_numeric_and_text_modes() {
        assert!(is_suspicious_interrupt_rate("1"));
        assert!(is_suspicious_interrupt_rate("3"));
        assert!(is_suspicious_interrupt_rate("Extreme"));
        assert!(!is_suspicious_interrupt_rate("Adaptive"));
    }

    #[test]
    fn enabled_parser_accepts_common_spellings() {
        assert!(looks_enabled("1"));
        assert!(looks_enabled("Enabled"));
        assert!(!looks_enabled("Disabled"));
    }

    #[test]
    fn wifi_adapter_detection_matches_desc_and_component_id() {
        assert!(looks_like_wifi_adapter("Intel(R) Wi-Fi 6 AX201", None));
        assert!(looks_like_wifi_adapter("Killer Adapter", Some("wlan")));
        assert!(!looks_like_wifi_adapter(
            "Intel(R) Ethernet Controller",
            None
        ));
    }

    #[test]
    fn virtual_adapter_detection_matches_host_only_and_vpn() {
        assert!(is_virtual_adapter(
            "VirtualBox Host-Only Ethernet Adapter",
            None
        ));
        assert!(is_virtual_adapter("Ethernet Adapter", Some("wintun")));
        assert!(!is_virtual_adapter(
            "Realtek PCIe GbE Family Controller",
            None
        ));
    }
}
