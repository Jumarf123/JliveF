use super::*;

pub(super) fn parse_gateway_open_tcp_ports(
    raw_commands: &[CommandArtifact],
) -> HashMap<String, Vec<u16>> {
    parse_open_tcp_ports(raw_commands, "tcp_probe_gateway_")
}

pub(super) fn parse_peer_open_tcp_ports(
    raw_commands: &[CommandArtifact],
) -> HashMap<String, Vec<u16>> {
    parse_open_tcp_ports(raw_commands, "tcp_probe_peer_")
}

fn parse_open_tcp_ports(
    raw_commands: &[CommandArtifact],
    prefix: &str,
) -> HashMap<String, Vec<u16>> {
    let re = Regex::new(r"remote=([0-9.]+):([0-9]+)").unwrap();
    let mut map = HashMap::<String, Vec<u16>>::new();
    for artifact in raw_commands
        .iter()
        .filter(|artifact| artifact.name.starts_with(prefix))
    {
        if !artifact.output.trim().eq_ignore_ascii_case("open") {
            continue;
        }
        let Some(captures) = re.captures(&artifact.command) else {
            continue;
        };
        let Some(port) = captures[2].parse::<u16>().ok() else {
            continue;
        };
        map.entry(captures[1].to_string()).or_default().push(port);
    }
    for ports in map.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    map
}

pub(super) fn parse_gateway_nbtstat(
    raw_commands: &[CommandArtifact],
) -> HashMap<String, NbtstatInfo> {
    parse_nbtstat_artifacts(raw_commands, "nbtstat_gateway_")
}

pub(super) fn parse_peer_nbtstat(raw_commands: &[CommandArtifact]) -> HashMap<String, NbtstatInfo> {
    parse_nbtstat_artifacts(raw_commands, "nbtstat_peer_")
}

fn parse_nbtstat_artifacts(
    raw_commands: &[CommandArtifact],
    prefix: &str,
) -> HashMap<String, NbtstatInfo> {
    let mac_re = Regex::new(r"(?i)MAC Address\s*=\s*([0-9A-F:-]{11,})").unwrap();
    let name_re =
        Regex::new(r"(?i)^\s*([^\r\n<]{1,32}?)\s*<([0-9A-F]{2})>\s+(UNIQUE|GROUP)").unwrap();
    let mut map = HashMap::new();

    for artifact in raw_commands
        .iter()
        .filter(|artifact| artifact.name.starts_with(prefix))
    {
        let ip = artifact
            .command
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .trim()
            .to_string();
        if ip.is_empty() {
            continue;
        }

        let mut info = NbtstatInfo::default();
        if let Some(captures) = mac_re.captures(&artifact.output) {
            info.mac = Some(normalize_mac_display(&captures[1]));
        }
        for line in artifact.output.lines() {
            if let Some(captures) = name_re.captures(line) {
                let name = captures[1].trim().to_string();
                let code = captures[2].to_ascii_uppercase();
                if !name.is_empty() {
                    info.names.push(format!("{}<{}>", name, code));
                }
                match code.as_str() {
                    "00" | "03" => info.workstation_service = true,
                    "20" => {
                        info.workstation_service = true;
                        info.file_server_service = true;
                    }
                    _ => {}
                }
            }
        }
        info.names.sort();
        info.names.dedup();
        map.insert(ip, info);
    }

    map
}

pub(super) fn parse_netsh_neighbor_macs(text: &str) -> HashMap<String, HashSet<String>> {
    let re = Regex::new(r"(?im)^\s*([0-9a-f:.%]+)\s+([0-9a-f-]{11,})\s+\S+").unwrap();
    let mut map = HashMap::<String, HashSet<String>>::new();
    for captures in re.captures_iter(text) {
        let ip = normalize_ip_literal(&captures[1]);
        let mac = normalize_mac_display(&captures[2]);
        if ip.is_empty() || mac == "unknown" {
            continue;
        }
        map.entry(ip).or_default().insert(mac);
    }
    map
}

pub(super) fn merge_neighbor_macs(
    first: &HashMap<String, HashSet<String>>,
    second: &HashMap<String, HashSet<String>>,
) -> HashMap<String, HashSet<String>> {
    let mut merged = first.clone();
    for (ip, macs) in second {
        merged.entry(ip.clone()).or_default().extend(macs.clone());
    }
    merged
}

pub(super) fn parse_portproxy_entries(text: &str) -> Vec<PortProxyEntry> {
    let re =
        Regex::new(r"(?im)^\s*([0-9a-f:.]+)\s+([0-9]+)\s+([0-9a-f:.]+)\s+([0-9]+)\s*$").unwrap();
    let mut entries = Vec::new();
    for captures in re.captures_iter(text) {
        let Some(listen_port) = captures[2].parse::<u16>().ok() else {
            continue;
        };
        let Some(connect_port) = captures[4].parse::<u16>().ok() else {
            continue;
        };
        entries.push(PortProxyEntry {
            listen_addr: normalize_ip_literal(&captures[1]),
            listen_port,
            connect_addr: normalize_ip_literal(&captures[3]),
            connect_port,
        });
    }
    entries
}

pub(super) fn parse_ipconfig_adapters(text: &str) -> Vec<AdapterBlock> {
    let header_re = Regex::new(r"(?i)^[^\r\n:]+(?:adapter|адаптер)\s+(.+):\s*$").unwrap();
    let line_re = Regex::new(r"^\s*([^.:\r\n]+?)[ .]*:\s*(.*)$").unwrap();
    let mut adapters = Vec::<AdapterBlock>::new();
    let mut current: Option<AdapterBlock> = None;
    let mut current_key = String::new();

    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(captures) = header_re.captures(trimmed) {
            if let Some(adapter) = current.take() {
                adapters.push(adapter);
            }
            current_key.clear();
            current = Some(AdapterBlock {
                name: captures[1].trim().to_string(),
                ..AdapterBlock::default()
            });
            continue;
        }

        let Some(adapter) = current.as_mut() else {
            continue;
        };

        if let Some(captures) = line_re.captures(trimmed) {
            current_key = captures[1].trim().to_string();
            let value = captures[2].trim();
            match current_key.to_ascii_lowercase().as_str() {
                "description" | "описание" => {
                    adapter.description = cleanup_ipconfig_value(value)
                }
                "physical address" | "физический адрес" => {
                    adapter.physical_address = normalize_mac_display(value)
                }
                "dhcp enabled" | "dhcp включен" | "dhcp включено" => {
                    adapter.dhcp_enabled = parse_yes_no(value)
                }
                "subnet mask" | "маска подсети" => {
                    let mask = cleanup_ipconfig_value(value);
                    if !mask.is_empty() {
                        adapter.subnet_masks.push(mask);
                    }
                }
                "default gateway" | "основной шлюз" => {
                    add_ips_for_key(adapter, "gateway", value);
                }
                "dhcp server" | "dhcp-сервер" | "dhcp сервер" => {
                    add_ips_for_key(adapter, "dhcp", value);
                }
                "dns servers" | "dns-серверы" | "dns servers " => {
                    add_ips_for_key(adapter, "dns", value);
                }
                "ipv4 address" | "ipv4-адрес" | "autoconfiguration ipv4 address" => {
                    add_ips_for_key(adapter, "ipv4", value);
                }
                _ => {}
            }
            continue;
        }

        if trimmed.starts_with(char::is_whitespace) && !current_key.is_empty() {
            let value = trimmed.trim();
            match current_key.to_ascii_lowercase().as_str() {
                "default gateway" | "основной шлюз" => {
                    add_ips_for_key(adapter, "gateway", value)
                }
                "dhcp server" | "dhcp-сервер" | "dhcp сервер" => {
                    add_ips_for_key(adapter, "dhcp", value)
                }
                "dns servers" | "dns-серверы" | "dns servers " => {
                    add_ips_for_key(adapter, "dns", value)
                }
                "ipv4 address" | "ipv4-адрес" | "autoconfiguration ipv4 address" => {
                    add_ips_for_key(adapter, "ipv4", value)
                }
                _ => {}
            }
        }
    }

    if let Some(adapter) = current.take() {
        adapters.push(adapter);
    }

    for adapter in &mut adapters {
        adapter.ipv4_addresses.sort();
        adapter.ipv4_addresses.dedup();
        adapter.subnet_masks.sort();
        adapter.subnet_masks.dedup();
        adapter.default_gateways.sort();
        adapter.default_gateways.dedup();
        adapter.dhcp_servers.sort();
        adapter.dhcp_servers.dedup();
        adapter.dns_servers.sort();
        adapter.dns_servers.dedup();
    }

    adapters
}

fn add_ips_for_key(adapter: &mut AdapterBlock, key: &str, value: &str) {
    for ip in extract_ipv4s(value) {
        match key {
            "ipv4" => adapter.ipv4_addresses.push(ip),
            "gateway" => adapter.default_gateways.push(ip),
            "dhcp" => adapter.dhcp_servers.push(ip),
            "dns" => adapter.dns_servers.push(ip),
            _ => {}
        }
    }
}

fn cleanup_ipconfig_value(value: &str) -> String {
    value
        .replace("(Preferred)", "")
        .replace("(Предпочтительно)", "")
        .replace("(Preferred )", "")
        .replace("(предпочтительно)", "")
        .trim_matches('.')
        .trim()
        .to_string()
}

fn parse_yes_no(value: &str) -> Option<bool> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("yes") || lower.contains("да") {
        Some(true)
    } else if lower.contains("no") || lower.contains("нет") {
        Some(false)
    } else {
        None
    }
}

pub(super) fn parse_arp_entries(text: &str) -> Vec<ArpEntry> {
    let re = Regex::new(r"(?im)^\s*([0-9.]+)\s+([0-9a-f-]{11,})\s+([a-zA-Zа-яА-Я]+)\s*$").unwrap();
    let mut entries = Vec::new();
    let mut current_interface = String::new();
    let interface_re = Regex::new(r"(?im)^Interface:\s*([0-9.]+)").unwrap();

    for line in text.lines() {
        if let Some(captures) = interface_re.captures(line) {
            current_interface = captures[1].to_string();
            continue;
        }
        if let Some(captures) = re.captures(line) {
            entries.push(ArpEntry {
                interface: current_interface.clone(),
                ip: captures[1].to_string(),
                mac: normalize_mac_display(&captures[2]),
                kind: captures[3].to_string(),
            });
        }
    }

    entries
}

pub(super) fn parse_pathping_hops(text: &str) -> Vec<PathHop> {
    let re = Regex::new(r"(?im)^\s*([0-9]+)\s+([0-9.]+)\s*$").unwrap();
    let mut hops = Vec::new();
    for captures in re.captures_iter(text) {
        let Some(hop) = captures[1].parse::<u32>().ok() else {
            continue;
        };
        let ip = captures[2].to_string();
        if !is_valid_ipv4(&ip) {
            continue;
        }
        hops.push(PathHop { hop, ip });
    }
    hops.sort_by_key(|hop| hop.hop);
    hops
}

pub(super) fn parse_gateway_ping_ttls(raw_commands: &[CommandArtifact]) -> HashMap<String, u16> {
    let re = Regex::new(r"(?i)ttl[=|:]\s*([0-9]+)").unwrap();
    let mut map = HashMap::new();
    for artifact in raw_commands
        .iter()
        .filter(|artifact| artifact.name.starts_with("ping_gateway_"))
    {
        let ip = artifact
            .command
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .trim()
            .to_string();
        if ip.is_empty() {
            continue;
        }
        let Some(captures) = re.captures(&artifact.output) else {
            continue;
        };
        let Some(ttl) = captures[1].parse::<u16>().ok() else {
            continue;
        };
        map.insert(ip, ttl);
    }
    map
}

pub(super) fn parse_netstat_tcp(text: &str) -> Vec<NetstatTcp> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if !(lower.starts_with("tcp") || lower.starts_with("udp")) {
            continue;
        }
        let columns = trimmed.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 4 || !columns[0].eq_ignore_ascii_case("tcp") {
            continue;
        }
        let local = split_socket(columns[1]);
        let remote = split_socket(columns[2]);
        let (Some((local_addr, local_port)), Some((remote_addr, remote_port))) = (local, remote)
        else {
            continue;
        };
        let (state, pid_text) = if columns.len() >= 5 {
            (columns[3].to_string(), columns[4])
        } else {
            continue;
        };
        let Some(pid) = pid_text.parse::<u32>().ok() else {
            continue;
        };
        entries.push(NetstatTcp {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        });
    }
    entries
}

fn split_socket(value: &str) -> Option<(String, u16)> {
    if value.starts_with('[') {
        let end = value.rfind(']')?;
        let addr = normalize_ip_literal(&value[..=end]);
        let port = value.get(end + 2..)?.parse::<u16>().ok()?;
        return Some((addr, port));
    }
    let (addr, port) = value.rsplit_once(':')?;
    Some((normalize_ip_literal(addr), port.parse::<u16>().ok()?))
}
