use super::models::{
    ConnectedDevice, CurrentConnection, HostedNetwork, NetworkProfile, ScanResult, VirtualAdapter,
    WlanEvent,
};
use chrono::{DateTime, Duration, Local};
use quick_xml::Reader;
use quick_xml::events::Event;
use rand::{Rng, distributions::Alphanumeric};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use wmi::{COMLibrary, WMIConnection};

const WHITELIST: &[&str] = &["LAPTOP-KPU3L0OC"];

#[derive(Deserialize, Debug)]
struct AdapterConfiguration {
    #[serde(rename = "IPEnabled")]
    ip_enabled: Option<bool>,
    #[serde(rename = "DefaultIPGateway")]
    default_gateway: Option<Vec<String>>,
    #[serde(rename = "DNSServerSearchOrder")]
    dns_servers: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct NetAdapter {
    #[serde(rename = "NetEnabled")]
    net_enabled: Option<bool>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
}

pub fn generate_random_report_name() -> String {
    let len = rand::thread_rng().gen_range(16usize..=24usize);
    let name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect();
    format!("{name}.html")
}

fn run_command(cmd: &str, args: &[&str], verbose: bool) -> Option<String> {
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if !output.status.success() && verbose {
                eprintln!(
                    "Command `{cmd} {}` exited with code {:?}",
                    args.join(" "),
                    output.status.code()
                );
            }
            Some(String::from_utf8_lossy(&output.stdout).to_string())
        }
        Err(err) => {
            if verbose {
                eprintln!("Failed to run `{cmd}`: {err}");
            }
            None
        }
    }
}

fn check_possible_variables() -> bool {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|name| WHITELIST.iter().any(|w| w.eq_ignore_ascii_case(&name)))
        .unwrap_or(false)
}

pub fn run_scan(hours_back: i64, verbose: bool) -> ScanResult {
    let start_time = Local::now() - Duration::hours(hours_back);
    let possible_variables = check_possible_variables();
    let mut result = ScanResult {
        start_time,
        hours_back,
        possible_variables,
        ..Default::default()
    };

    result.wlan_events = collect_wlan_events(start_time, verbose);
    result.network_profiles = collect_network_profiles(possible_variables, verbose);

    let current = collect_current_connection(possible_variables, verbose);
    if let Some(conn) = current.0 {
        if conn.is_hotspot && !possible_variables {
            result.suspicious_activities.push(format!(
                "Currently connected to hotspot: {} ({} indicators)",
                conn.ssid,
                conn.hotspot_indicators.len()
            ));
        }
        result.faker_detected |= current.1;
        result.faker_indicators.extend(current.2);
        result.current_connection = Some(conn);
    }

    let hosted = collect_hosted_network(possible_variables, verbose);
    if hosted.active {
        result.suspicious_activities.push(format!(
            "Active hosted network '{}' with {} client(s)",
            hosted.ssid, hosted.clients
        ));
    }
    result.hosted_network = hosted;

    result.mobile_hotspot_active = check_mobile_hotspot_service(possible_variables, verbose);
    if result.mobile_hotspot_active {
        result
            .suspicious_activities
            .push("Windows Mobile Hotspot service (icssvc) is running".to_string());
    }

    let virtual_adapters = collect_virtual_adapters(possible_variables, verbose);
    if !virtual_adapters.is_empty() {
        result.suspicious_activities.push(format!(
            "{} virtual network adapter(s) detected",
            virtual_adapters.len()
        ));
    }
    result.virtual_adapters = virtual_adapters;

    result.connected_devices = collect_connected_devices(verbose);
    result
}

fn collect_wlan_events(start_time: DateTime<Local>, verbose: bool) -> Vec<WlanEvent> {
    let mut events = Vec::new();
    if let Some(output) = run_command(
        "wevtutil",
        &[
            "qe",
            "Microsoft-Windows-WLAN-AutoConfig/Operational",
            "/c:100",
            "/rd:true",
            "/f:xml",
        ],
        verbose,
    ) {
        let mut reader = Reader::from_str(&output);
        reader.trim_text(true);
        let mut buf = Vec::new();

        let mut current_time: Option<DateTime<Local>> = None;
        let mut current_id: Option<u32> = None;
        let mut current_message: Option<String> = None;
        let mut in_message = false;
        let mut in_event_id = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"TimeCreated" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"SystemTime" {
                                if let Ok(val) = attr.unescape_value() {
                                    if let Ok(dt) = DateTime::parse_from_rfc3339(&val) {
                                        current_time = Some(dt.with_timezone(&Local));
                                    }
                                }
                            }
                        }
                    }
                    b"EventID" => {
                        in_event_id = true;
                    }
                    b"Message" => {
                        in_message = true;
                    }
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if in_event_id {
                        if let Ok(text) = e.unescape() {
                            if let Ok(id) = text.parse::<u32>() {
                                current_id = Some(id);
                            }
                        }
                    } else if in_message {
                        if let Ok(text) = e.unescape() {
                            current_message = Some(text.to_string());
                        }
                    }
                }
                Ok(Event::End(ref e)) => match e.name().as_ref() {
                    b"Event" => {
                        if let (Some(t), Some(id)) = (current_time, current_id) {
                            if t >= start_time {
                                let mut message = current_message.unwrap_or_default();
                                if message.len() > 200 {
                                    message.truncate(200);
                                }
                                events.push(WlanEvent {
                                    time_created: t,
                                    event_id: id,
                                    message,
                                });
                            }
                        }
                        current_time = None;
                        current_id = None;
                        current_message = None;
                        in_message = false;
                        in_event_id = false;
                    }
                    b"EventID" => in_event_id = false,
                    b"Message" => in_message = false,
                    _ => {}
                },
                Ok(Event::Eof) => break,
                Err(e) => {
                    if verbose {
                        eprintln!("Failed to parse WLAN event log: {e}");
                    }
                    break;
                }
                _ => {}
            }
            buf.clear();
        }
    }
    events
}

fn collect_network_profiles(possible_variables: bool, verbose: bool) -> Vec<NetworkProfile> {
    let mut profiles = Vec::new();
    let regex = Regex::new(r"All User Profile\s*:\s*(.+)").unwrap();
    let hotspot_regex =
        Regex::new(r"(?i)Android|iPhone|iPad|Galaxy|Pixel|OnePlus|Xiaomi|DIRECT-|SM-|GT-").unwrap();

    if let Some(output) = run_command("netsh", &["wlan", "show", "profiles"], verbose) {
        for line in output.lines() {
            if let Some(cap) = regex.captures(line) {
                let ssid = cap[1].trim().to_string();
                if ssid.is_empty() {
                    continue;
                }
                let mut is_hotspot = hotspot_regex.is_match(&ssid);
                if possible_variables {
                    is_hotspot = false;
                }
                profiles.push(NetworkProfile { ssid, is_hotspot });
            }
        }
    }
    profiles
}

fn collect_current_connection(
    possible_variables: bool,
    verbose: bool,
) -> (Option<CurrentConnection>, bool, Vec<String>) {
    let interface_output = match run_command("netsh", &["wlan", "show", "interfaces"], verbose) {
        Some(out) => out,
        None => return (None, false, Vec::new()),
    };

    let ssid_re = Regex::new(r"^\s*SSID\s*:\s*(.+)$").unwrap();
    let state_re = Regex::new(r"^\s*State\s*:\s*(.+)$").unwrap();
    let bssid_re = Regex::new(r"^\s*BSSID\s*:\s*(.+)$").unwrap();
    let network_type_re = Regex::new(r"^\s*Network type\s*:\s*(.+)$").unwrap();
    let radio_type_re = Regex::new(r"^\s*Radio type\s*:\s*(.+)$").unwrap();
    let channel_re = Regex::new(r"^\s*Channel\s*:\s*(.+)$").unwrap();
    let signal_re = Regex::new(r"^\s*Signal\s*:\s*(.+)$").unwrap();

    let mut ssid = None;
    let mut state = None;
    let mut bssid = "N/A".to_string();
    let mut network_type = "N/A".to_string();
    let mut radio_type = "N/A".to_string();
    let mut channel = "N/A".to_string();
    let mut signal = "N/A".to_string();

    for line in interface_output.lines() {
        if ssid.is_none() {
            if let Some(cap) = ssid_re.captures(line) {
                ssid = Some(cap[1].trim().to_string());
            }
        }
        if state.is_none() {
            if let Some(cap) = state_re.captures(line) {
                state = Some(cap[1].trim().to_string());
            }
        }
        if bssid == "N/A" {
            if let Some(cap) = bssid_re.captures(line) {
                bssid = cap[1].trim().to_string();
            }
        }
        if network_type == "N/A" {
            if let Some(cap) = network_type_re.captures(line) {
                network_type = cap[1].trim().to_string();
            }
        }
        if radio_type == "N/A" {
            if let Some(cap) = radio_type_re.captures(line) {
                radio_type = cap[1].trim().to_string();
            }
        }
        if channel == "N/A" {
            if let Some(cap) = channel_re.captures(line) {
                channel = cap[1].trim().to_string();
            }
        }
        if signal == "N/A" {
            if let Some(cap) = signal_re.captures(line) {
                signal = cap[1].trim().to_string();
            }
        }
    }

    if ssid.is_none() || state.is_none() {
        return (None, false, Vec::new());
    }

    let current_state = state.unwrap();
    if current_state.to_lowercase() != "connected" {
        return (
            Some(CurrentConnection {
                ssid: ssid.unwrap(),
                state: current_state,
                bssid,
                network_type,
                radio_type,
                channel,
                signal,
                is_hotspot: false,
                hotspot_indicators: Vec::new(),
            }),
            false,
            Vec::new(),
        );
    }

    let mut is_hotspot = false;
    let mut hotspot_indicators = Vec::new();
    let mut faker_detected = false;
    let mut faker_indicators = Vec::new();

    if !possible_variables {
        let name_patterns = [
            "Android",
            "iPhone",
            "iPad",
            "Galaxy",
            "Pixel",
            "OnePlus",
            "Xiaomi",
            "Huawei",
            "Oppo",
            "Vivo",
            "Realme",
            "Nokia",
            "DIRECT-",
            "SM-[A-Z0-9]",
            "GT-[A-Z0-9]",
            "Redmi",
            "Mi ",
            "'s iPhone",
            "'s Galaxy",
            "'s Pixel",
            "'s Android",
        ];

        for pattern in name_patterns.iter() {
            let regex = Regex::new(&format!("(?i){}", pattern)).unwrap();
            if let Some(ref s) = ssid {
                if regex.is_match(s) {
                    is_hotspot = true;
                    hotspot_indicators
                        .push(format!("SSID matches mobile device pattern: {pattern}"));
                    break;
                }
            }
        }

        if bssid != "N/A" {
            let clean_bssid = bssid.replace(':', "").replace('-', "").to_uppercase();
            let mobile_ouis: HashMap<&str, &str> = HashMap::from([
                ("00505", "Samsung"),
                ("0025BC", "Apple"),
                ("0026B", "Apple"),
                ("A8667", "Google Pixel"),
                ("F0D1A", "Google"),
                ("5C8D4", "Xiaomi"),
                ("F8A45", "OnePlus"),
                ("DC44B", "Huawei"),
                ("B0B98", "Samsung Galaxy"),
            ]);
            for (prefix, vendor) in mobile_ouis.iter() {
                if clean_bssid.starts_with(prefix) {
                    is_hotspot = true;
                    hotspot_indicators.push(format!("BSSID indicates {vendor} device"));
                    break;
                }
            }

            if let Some(second) = clean_bssid.chars().nth(1) {
                if matches!(second, '2' | '6' | 'A' | 'a' | 'E' | 'e') {
                    hotspot_indicators.push(
                        "BSSID uses locally administered address (common in hotspots)".to_string(),
                    );
                    is_hotspot = true;
                }
            }
        }

        if let Some(gateway_info) = get_gateway_and_dns(verbose) {
            let gateway = gateway_info.0;
            let dns_servers = gateway_info.1;

            if gateway.starts_with("192.168.137.") {
                is_hotspot = true;
                faker_detected = true;
                faker_indicators
                    .push("Windows PC Hotspot gateway detected (192.168.137.x)".to_string());
                hotspot_indicators.push(
                    "Gateway indicates Windows PC Mobile Hotspot (192.168.137.x range) - FAKER INDICATOR".to_string(),
                );
            }

            let hotspot_gateways = [
                "192.168.43.1",
                "192.168.137.1",
                "192.168.42.1",
                "192.168.49.1",
            ];
            if hotspot_gateways.contains(&gateway.as_str()) {
                is_hotspot = true;
                hotspot_indicators.push(format!(
                    "Gateway IP ({gateway}) is typical for mobile hotspots"
                ));
                if gateway == "192.168.137.1" {
                    faker_detected = true;
                    faker_indicators.push(format!("Windows PC Hotspot gateway: {gateway}"));
                }
            }

            if gateway.starts_with("192.168.43.") {
                is_hotspot = true;
                hotspot_indicators
                    .push("Gateway indicates Android hotspot (192.168.43.x range)".to_string());
            }

            if let Some(dns_first) = dns_servers.get(0) {
                if dns_first == &gateway {
                    hotspot_indicators.push(
                        "DNS server is same as gateway (typical hotspot configuration)".to_string(),
                    );
                    is_hotspot = true;
                }
            }
        }

        if network_type == "Infrastructure" {
            if let Ok(channel_num) = channel.trim().parse::<i32>() {
                if [1, 6, 11].contains(&channel_num) {
                    hotspot_indicators.push(format!(
                        "Using common mobile hotspot channel: {channel_num}"
                    ));
                }
            }
        }
    }

    (
        Some(CurrentConnection {
            ssid: ssid.unwrap_or_else(|| "N/A".to_string()),
            state: current_state,
            bssid,
            network_type,
            radio_type,
            channel,
            signal,
            is_hotspot,
            hotspot_indicators,
        }),
        faker_detected,
        faker_indicators,
    )
}

fn collect_hosted_network(possible_variables: bool, verbose: bool) -> HostedNetwork {
    let mut hosted = HostedNetwork::default();
    let status_re = Regex::new(r"Status\s*:\s*(.+)").unwrap();
    let ssid_re = Regex::new(r#"SSID name\s*:\s*"(.+)""#).unwrap();
    let clients_re = Regex::new(r"Number of clients\s*:\s*(\d+)").unwrap();

    if let Some(output) = run_command("netsh", &["wlan", "show", "hostednetwork"], verbose) {
        let mut status = None;
        for line in output.lines() {
            if status.is_none() {
                if let Some(cap) = status_re.captures(line) {
                    status = Some(cap[1].trim().to_string());
                }
            }
        }

        if let Some(stat) = status {
            hosted.active = stat.eq_ignore_ascii_case("Started");
        }

        if possible_variables {
            hosted.active = false;
        }

        if hosted.active {
            for line in output.lines() {
                if hosted.ssid == "N/A" {
                    if let Some(cap) = ssid_re.captures(line) {
                        hosted.ssid = cap[1].to_string();
                    }
                }
                if hosted.clients == 0 {
                    if let Some(cap) = clients_re.captures(line) {
                        hosted.clients = cap[1].parse::<u32>().unwrap_or(0);
                    }
                }
            }
        }
    }
    hosted
}

fn check_mobile_hotspot_service(possible_variables: bool, verbose: bool) -> bool {
    if possible_variables {
        return false;
    }
    unsafe {
        use windows::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_STATUS_PROCESS,
        };
        use windows::core::w;

        let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
            Ok(handle) => handle,
            Err(_) => {
                if verbose {
                    eprintln!("Failed to open Service Control Manager");
                }
                return false;
            }
        };

        let service = match OpenServiceW(scm, w!("icssvc"), SERVICE_QUERY_STATUS) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                if verbose {
                    eprintln!("Failed to open icssvc");
                }
                return false;
            }
        };

        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed: u32 = 0;
        let status_slice = std::slice::from_raw_parts_mut(
            &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
        );

        let ok = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            Some(status_slice),
            &mut bytes_needed,
        );
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
        if ok.is_ok() {
            status.dwCurrentState == SERVICE_RUNNING
        } else {
            if verbose {
                eprintln!("Failed to query icssvc status");
            }
            false
        }
    }
}

fn collect_virtual_adapters(possible_variables: bool, verbose: bool) -> Vec<VirtualAdapter> {
    let mut adapters_out = Vec::new();
    if let Ok(com) = COMLibrary::new() {
        if let Ok(conn) = WMIConnection::new(com) {
            let res: Result<Vec<NetAdapter>, _> = conn.raw_query(
                "SELECT NetEnabled, Description, Name, MACAddress FROM Win32_NetworkAdapter",
            );
            match res {
                Ok(adapters) => {
                    let regex = Regex::new(r"(?i)Virtual|Hosted|Wi-Fi Direct|TAP").unwrap();
                    for adapter in adapters {
                        let enabled = adapter.net_enabled.unwrap_or(false);
                        let desc = adapter.description.unwrap_or_default();
                        if enabled && regex.is_match(&desc) && !possible_variables {
                            adapters_out.push(VirtualAdapter {
                                name: adapter.name.unwrap_or_default(),
                                description: desc,
                                mac: adapter.mac_address.unwrap_or_default(),
                            });
                        }
                    }
                }
                Err(_) => {
                    if verbose {
                        eprintln!("Failed to query WMI for network adapters");
                    }
                }
            }
        }
    } else if verbose {
        eprintln!("Failed to initialize COM for WMI");
    }
    adapters_out
}

fn collect_connected_devices(verbose: bool) -> Vec<ConnectedDevice> {
    let mut devices = Vec::new();
    let regex = Regex::new(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(dynamic|static)").unwrap();
    if let Some(output) = run_command("arp", &["-a"], verbose) {
        for line in output.lines() {
            if let Some(cap) = regex.captures(line) {
                let ip = cap[1].to_string();
                let mac = cap[2].to_string();
                let kind = cap[3].to_string();
                if ip.starts_with("192.168.") && kind.eq_ignore_ascii_case("dynamic") {
                    devices.push(ConnectedDevice {
                        ip,
                        mac,
                        device_type: kind,
                    });
                }
            }
        }
    }
    devices
}

fn get_gateway_and_dns(verbose: bool) -> Option<(String, Vec<String>)> {
    if let Ok(com) = COMLibrary::new() {
        if let Ok(conn) = WMIConnection::new(com) {
            let res: Result<Vec<AdapterConfiguration>, _> = conn.raw_query(
                "SELECT IPEnabled, DefaultIPGateway, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
            );
            match res {
                Ok(configs) => {
                    for cfg in configs {
                        if cfg.ip_enabled.unwrap_or(false) {
                            if let Some(gws) = cfg.default_gateway {
                                if let Some(first) = gws.into_iter().next() {
                                    let dns = cfg.dns_servers.unwrap_or_default();
                                    return Some((first, dns));
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    if verbose {
                        eprintln!("Failed to query WMI for gateway/DNS");
                    }
                }
            }
        } else if verbose {
            eprintln!("Failed to establish WMI connection");
        }
    } else if verbose {
        eprintln!("Failed to initialize COM for gateway detection");
    }
    None
}
