use super::*;
use serde_json::Value;

pub(super) fn add_pktmon_probe_filters(
    raw_commands: &mut Vec<CommandArtifact>,
    adapters: &[AdapterBlock],
    probe_ports: &[u16],
) {
    let gateways = adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .filter(|gateway| is_private_ipv4(gateway))
        .cloned()
        .collect::<HashSet<_>>();

    if gateways.is_empty() {
        for port in probe_ports {
            let port_text = port.to_string();
            let tcp_name = format!("JliveF_MC_{port}_TCP");
            collect_fresh_command(
                raw_commands,
                &format!("pktmon_filter_add_{port}_tcp"),
                "pktmon",
                &["filter", "add", &tcp_name, "-t", "TCP", "-p", &port_text],
            );

            let udp_name = format!("JliveF_MC_{port}_UDP");
            collect_fresh_command(
                raw_commands,
                &format!("pktmon_filter_add_{port}_udp"),
                "pktmon",
                &["filter", "add", &udp_name, "-t", "UDP", "-p", &port_text],
            );
        }
        return;
    }

    for gateway in gateways {
        let gateway_id = gateway.replace('.', "_");
        for port in probe_ports {
            let port_text = port.to_string();
            let tcp_name = format!("JliveF_MC_{gateway_id}_{port}_TCP");
            collect_fresh_command(
                raw_commands,
                &format!("pktmon_filter_add_{gateway_id}_{port}_tcp"),
                "pktmon",
                &[
                    "filter", "add", &tcp_name, "-i", &gateway, "-t", "TCP", "-p", &port_text,
                ],
            );

            let udp_name = format!("JliveF_MC_{gateway_id}_{port}_UDP");
            collect_fresh_command(
                raw_commands,
                &format!("pktmon_filter_add_{gateway_id}_{port}_udp"),
                "pktmon",
                &[
                    "filter", "add", &udp_name, "-i", &gateway, "-t", "UDP", "-p", &port_text,
                ],
            );
        }
    }
}

pub(super) fn add_pktmon_live_flow_filters(
    raw_commands: &mut Vec<CommandArtifact>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
) {
    let client_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if client_flows.is_empty() {
        return;
    }

    let relay_pids = collect_local_proxy_relay_pids(process_map, netstat_entries, minecraft_ports);
    let mut endpoints = client_flows
        .iter()
        .map(|flow| (flow.remote_addr.clone(), flow.remote_port))
        .collect::<HashSet<_>>();
    for entry in netstat_entries {
        if !relay_pids.contains(&entry.pid) {
            continue;
        }
        if !matches!(
            entry.state.to_ascii_uppercase().as_str(),
            "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
        ) {
            continue;
        }
        if entry.remote_port == 0
            || is_wildcard_ip(&entry.remote_addr)
            || is_loopback_ip(&entry.remote_addr)
        {
            continue;
        }
        endpoints.insert((entry.remote_addr.clone(), entry.remote_port));
    }

    let mut endpoints = endpoints.into_iter().collect::<Vec<_>>();
    endpoints.sort();
    for (remote_addr, remote_port) in endpoints {
        let safe_id = remote_addr
            .chars()
            .map(|ch| match ch {
                '.' | ':' | '%' | '-' => '_',
                other => other,
            })
            .collect::<String>();
        let remote_port_text = remote_port.to_string();
        let name = format!("JliveF_FLOW_{safe_id}_{remote_port}_TCP");
        collect_fresh_command(
            raw_commands,
            &format!("pktmon_filter_add_flow_{safe_id}_{remote_port}_tcp"),
            "pktmon",
            &[
                "filter",
                "add",
                &name,
                "-i",
                &remote_addr,
                "-t",
                "TCP",
                "-p",
                &remote_port_text,
            ],
        );
    }
}

pub(super) fn detect_pktmon(
    findings: &mut Vec<Finding>,
    status: &str,
    filters: &str,
    counters: &str,
    counters_json: &str,
    has_flow_context: bool,
    probe_ports: &[u16],
) {
    let combined = format!("{status}\n{filters}\n{counters}\n{counters_json}").to_lowercase();
    let mut details = Vec::new();
    if probe_ports
        .iter()
        .any(|port| combined.contains(&port.to_string()))
        && pktmon_counters_have_packets(counters, counters_json)
        && has_flow_context
    {
        details.push(
            "pktmon Minecraft/proxy port filters observed numeric packet counters".to_string(),
        );
    }

    if !details.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "pktmon".to_string(),
            title: "Packet Monitor has proxy-port related state".to_string(),
            details,
        });
    }
}

fn pktmon_counters_have_packets(counters: &str, counters_json: &str) -> bool {
    pktmon_counters_have_packets_from_json(counters_json)
        .unwrap_or_else(|| pktmon_counters_have_packets_from_text(counters))
}

fn pktmon_counters_have_packets_from_json(counters_json: &str) -> Option<bool> {
    let trimmed = counters_json.trim();
    if trimmed.is_empty() {
        return None;
    }
    let value = serde_json::from_str::<Value>(trimmed).ok()?;
    let mut saw_counter = false;
    if pktmon_json_has_packets(&value, &mut saw_counter) {
        return Some(true);
    }
    if saw_counter { Some(false) } else { None }
}

fn pktmon_counters_have_packets_from_text(counters: &str) -> bool {
    let lower = counters.to_lowercase();
    if lower.contains("all counters are zero")
        || lower.contains("у всех счетчиков нулевые")
        || lower.contains("no counters")
        || lower.contains("нет счетчиков")
        || lower.contains("нулевые показания")
    {
        return false;
    }

    let re = Regex::new(r"(?i)(\d+)\s+(\d+)\s*$").unwrap();
    for line in counters.lines() {
        if let Some(captures) = re.captures(line.trim()) {
            let packets = captures
                .get(1)
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(0);
            if packets > 0 {
                return true;
            }
        }
    }

    false
}

fn pktmon_json_has_packets(value: &Value, saw_counter: &mut bool) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| pktmon_json_has_packets(item, saw_counter)),
        Value::Object(map) => {
            for direction in ["Inbound", "Outbound"] {
                if let Some(packets) = map
                    .get(direction)
                    .and_then(|value| value.get("Packets"))
                    .and_then(Value::as_u64)
                {
                    *saw_counter = true;
                    if packets > 0 {
                        return true;
                    }
                }
            }

            map.values()
                .any(|item| pktmon_json_has_packets(item, saw_counter))
        }
        _ => false,
    }
}
