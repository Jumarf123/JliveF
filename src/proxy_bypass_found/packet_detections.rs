use super::*;

pub(super) fn detect_local_proxy_chain(
    findings: &mut Vec<Finding>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    packet_capture_analysis: Option<&PacketCaptureAnalysis>,
) {
    let upstream_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if upstream_flows.is_empty() {
        return;
    }

    let mut remote_to_clients = HashMap::<(String, u16), Vec<&NetstatTcp>>::new();
    for flow in &upstream_flows {
        remote_to_clients
            .entry((flow.remote_addr.clone(), flow.remote_port))
            .or_default()
            .push(flow);
    }

    let relay_listener_ports = netstat_entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state.to_ascii_uppercase().as_str(),
                "LISTEN" | "LISTENING"
            ) && is_loopback_ip(&entry.local_addr)
        })
        .fold(HashMap::<u32, HashSet<u16>>::new(), |mut acc, entry| {
            acc.entry(entry.pid).or_default().insert(entry.local_port);
            acc
        });

    if relay_listener_ports.is_empty() {
        return;
    }

    let mut high_details = Vec::new();
    let mut medium_details = Vec::new();

    for (relay_pid, listener_ports) in relay_listener_ports {
        let Some(relay_process) = process_map.get(&relay_pid) else {
            continue;
        };
        if is_minecraft_client_process(&relay_process.name, &relay_process.command_line) {
            continue;
        }

        let loopback_peers = netstat_entries
            .iter()
            .filter(|entry| entry.pid == relay_pid)
            .filter(|entry| {
                matches!(
                    entry.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                ) && is_loopback_ip(&entry.local_addr)
                    && is_loopback_ip(&entry.remote_addr)
                    && (listener_ports.contains(&entry.local_port)
                        || listener_ports.contains(&entry.remote_port))
            })
            .collect::<Vec<_>>();
        if loopback_peers.is_empty() && listener_ports.is_empty() {
            continue;
        }

        let relay_upstreams = netstat_entries
            .iter()
            .filter(|entry| entry.pid == relay_pid)
            .filter(|entry| {
                matches!(
                    entry.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                ) && entry.remote_port != 0
                    && !is_wildcard_ip(&entry.remote_addr)
                    && !is_loopback_ip(&entry.remote_addr)
                    && remote_to_clients
                        .contains_key(&(entry.remote_addr.clone(), entry.remote_port))
            })
            .collect::<Vec<_>>();
        if relay_upstreams.is_empty() {
            continue;
        }

        let mut shared_endpoints = Vec::new();
        let mut packet_confirmed = false;
        for relay_flow in &relay_upstreams {
            if let Some(client_flows) =
                remote_to_clients.get(&(relay_flow.remote_addr.clone(), relay_flow.remote_port))
            {
                for client_flow in client_flows {
                    if client_flow.pid == relay_pid {
                        continue;
                    }
                    let client_packets = packet_activity_for_tuple(
                        packet_capture_analysis,
                        client_flow.pid,
                        &client_flow.local_addr,
                        client_flow.local_port,
                        &client_flow.remote_addr,
                        client_flow.remote_port,
                    );
                    let relay_packets = packet_activity_for_tuple(
                        packet_capture_analysis,
                        relay_flow.pid,
                        &relay_flow.local_addr,
                        relay_flow.local_port,
                        &relay_flow.remote_addr,
                        relay_flow.remote_port,
                    );
                    if client_packets.is_some() && relay_packets.is_some() {
                        packet_confirmed = true;
                    }
                    shared_endpoints.push(format!(
                        "client PID {} {}:{} -> {}:{} | relay PID {} {}:{} -> {}:{} | packets client={:?} relay={:?}",
                        client_flow.pid,
                        client_flow.local_addr,
                        client_flow.local_port,
                        client_flow.remote_addr,
                        client_flow.remote_port,
                        relay_pid,
                        relay_flow.local_addr,
                        relay_flow.local_port,
                        relay_flow.remote_addr,
                        relay_flow.remote_port,
                        client_packets,
                        relay_packets
                    ));
                }
            }
        }
        if shared_endpoints.is_empty() {
            continue;
        }

        let relay_text = format!(
            "{} {} {}",
            relay_process.name, relay_process.path, relay_process.command_line
        )
        .to_lowercase();
        let relay_listener_detail = listener_ports
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|port| format!("127.0.0.1:{port}"))
            .collect::<Vec<_>>();
        let loopback_detail = loopback_peers
            .iter()
            .map(|entry| {
                format!(
                    "{}:{} -> {}:{} {}",
                    entry.local_addr,
                    entry.local_port,
                    entry.remote_addr,
                    entry.remote_port,
                    entry.state
                )
            })
            .collect::<Vec<_>>();
        let mut details = vec![format!(
            "Relay PID {} {} | {}",
            relay_pid,
            relay_process.name,
            truncate_text(&relay_process.command_line, 260)
        )];
        details.push(format!("loopback_listeners={:?}", relay_listener_detail));
        details.push(format!("loopback_sessions={:?}", loopback_detail));
        details.extend(shared_endpoints);
        if packet_confirmed {
            details.push(
                "packet_capture confirms concurrent packets on both the client flow and relay flow"
                    .to_string(),
            );
        }

        let structural_proxy_chain =
            !loopback_peers.is_empty() && !relay_upstreams.is_empty() && !listener_ports.is_empty();
        if relay_text.contains("faker")
            || relay_text.contains("net.java.faker")
            || relay_text.contains("\\faker")
            || relay_text.contains("faker-")
        {
            high_details.extend(details);
            continue;
        }

        if packet_confirmed && structural_proxy_chain {
            high_details.extend(details);
        } else if structural_proxy_chain {
            medium_details.extend(details);
        }
    }

    if !high_details.is_empty() {
        high_details.sort();
        high_details.dedup();
        findings.push(Finding {
            confidence: Confidence::High,
            category: "local_proxy_chain".to_string(),
            title: "Separate local process is proxying Minecraft traffic".to_string(),
            details: high_details,
        });
    } else if !medium_details.is_empty() {
        medium_details.sort();
        medium_details.dedup();
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "local_proxy_chain".to_string(),
            title: "Local process chain around Minecraft needs review".to_string(),
            details: medium_details,
        });
    }
}

pub(super) fn detect_packet_relay_correlation(
    findings: &mut Vec<Finding>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    packet_capture_analysis: Option<&PacketCaptureAnalysis>,
) {
    let Some(analysis) = packet_capture_analysis else {
        return;
    };

    let client_upstreams =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if client_upstreams.is_empty() {
        return;
    }

    let relay_pids = collect_local_proxy_relay_pids(process_map, netstat_entries, minecraft_ports);
    if relay_pids.is_empty() {
        return;
    }

    let loopback_listener_ports = netstat_entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state.to_ascii_uppercase().as_str(),
                "LISTEN" | "LISTENING"
            ) && is_loopback_ip(&entry.local_addr)
        })
        .fold(HashMap::<u32, HashSet<u16>>::new(), |mut acc, entry| {
            acc.entry(entry.pid).or_default().insert(entry.local_port);
            acc
        });

    let mut remote_to_clients = HashMap::<(String, u16), Vec<&NetstatTcp>>::new();
    for flow in &client_upstreams {
        remote_to_clients
            .entry((flow.remote_addr.clone(), flow.remote_port))
            .or_default()
            .push(flow);
    }

    let mut high = Vec::new();
    let mut medium = Vec::new();

    for relay_pid in relay_pids {
        let Some(relay_process) = process_map.get(&relay_pid) else {
            continue;
        };
        let listener_ports = loopback_listener_ports
            .get(&relay_pid)
            .cloned()
            .unwrap_or_default();
        let has_loopback_session = netstat_entries.iter().any(|loopback| {
            loopback.pid == relay_pid
                && matches!(
                    loopback.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                )
                && is_loopback_ip(&loopback.local_addr)
                && is_loopback_ip(&loopback.remote_addr)
                && (listener_ports.contains(&loopback.local_port)
                    || listener_ports.contains(&loopback.remote_port))
        });
        if listener_ports.is_empty() && !has_loopback_session {
            continue;
        }

        let relay_upstreams = netstat_entries
            .iter()
            .filter(|entry| entry.pid == relay_pid)
            .filter(|entry| {
                matches!(
                    entry.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                ) && entry.remote_port != 0
                    && !is_wildcard_ip(&entry.remote_addr)
                    && !is_loopback_ip(&entry.remote_addr)
                    && remote_to_clients
                        .contains_key(&(entry.remote_addr.clone(), entry.remote_port))
            })
            .collect::<Vec<_>>();
        if relay_upstreams.is_empty() {
            continue;
        }

        for relay_flow in relay_upstreams {
            let Some(relay_stat) = find_packet_tuple_stat(
                Some(analysis),
                relay_flow.pid,
                &relay_flow.local_addr,
                relay_flow.local_port,
                &relay_flow.remote_addr,
                relay_flow.remote_port,
            ) else {
                continue;
            };
            let Some(client_flows) =
                remote_to_clients.get(&(relay_flow.remote_addr.clone(), relay_flow.remote_port))
            else {
                continue;
            };

            for client_flow in client_flows {
                if client_flow.pid == relay_pid {
                    continue;
                }
                let Some(client_stat) = find_packet_tuple_stat(
                    Some(analysis),
                    client_flow.pid,
                    &client_flow.local_addr,
                    client_flow.local_port,
                    &client_flow.remote_addr,
                    client_flow.remote_port,
                ) else {
                    continue;
                };

                let overlap = packet_tuple_windows_overlap(client_stat, relay_stat);
                let packet_ratio = packet_similarity_ratio(
                    packet_tuple_total_packets(client_stat),
                    packet_tuple_total_packets(relay_stat),
                );
                let payload_ratio = packet_similarity_ratio(
                    client_stat.outbound_payload_bytes + client_stat.inbound_payload_bytes,
                    relay_stat.outbound_payload_bytes + relay_stat.inbound_payload_bytes,
                );
                let client_bidirectional = packet_tuple_has_bidirectional_payload(client_stat);
                let relay_bidirectional = packet_tuple_has_bidirectional_payload(relay_stat);
                let handshake_match = packet_handshake_signature(client_stat)
                    == packet_handshake_signature(relay_stat)
                    && packet_handshake_signature(client_stat).is_some();

                let detail = format!(
                    "client PID {} {}:{} -> {}:{} | relay PID {} {}:{} -> {}:{} | loopback_listeners={:?} loopback_session={} overlap={} client_packets={} relay_packets={} packet_ratio={:.2} payload_ratio={:.2} client_handshake={:?} relay_handshake={:?}",
                    client_flow.pid,
                    client_flow.local_addr,
                    client_flow.local_port,
                    client_flow.remote_addr,
                    client_flow.remote_port,
                    relay_pid,
                    relay_flow.local_addr,
                    relay_flow.local_port,
                    relay_flow.remote_addr,
                    relay_flow.remote_port,
                    listener_ports,
                    has_loopback_session,
                    overlap,
                    packet_activity_for_tuple(
                        Some(analysis),
                        client_flow.pid,
                        &client_flow.local_addr,
                        client_flow.local_port,
                        &client_flow.remote_addr,
                        client_flow.remote_port
                    )
                    .unwrap_or_else(|| "none".to_string()),
                    packet_activity_for_tuple(
                        Some(analysis),
                        relay_flow.pid,
                        &relay_flow.local_addr,
                        relay_flow.local_port,
                        &relay_flow.remote_addr,
                        relay_flow.remote_port
                    )
                    .unwrap_or_else(|| "none".to_string()),
                    packet_ratio,
                    payload_ratio,
                    packet_handshake_signature(client_stat),
                    packet_handshake_signature(relay_stat)
                );

                if overlap
                    && client_bidirectional
                    && relay_bidirectional
                    && packet_tuple_total_packets(client_stat) >= 4
                    && packet_tuple_total_packets(relay_stat) >= 4
                    && (packet_ratio >= 0.35 || payload_ratio >= 0.25 || handshake_match)
                {
                    high.push(format!(
                        "Packet capture shows a duplicated upstream Minecraft conversation being relayed through a local process: Relay PID {} {} | {}",
                        relay_pid,
                        relay_process.name,
                        detail
                    ));
                } else if overlap
                    && packet_tuple_total_packets(client_stat) >= 3
                    && packet_tuple_total_packets(relay_stat) >= 3
                    && packet_ratio >= 0.20
                {
                    medium.push(format!(
                        "Packet capture shows two local processes carrying the same Minecraft upstream endpoint with overlapping traffic: Relay PID {} {} | {}",
                        relay_pid,
                        relay_process.name,
                        detail
                    ));
                }
            }
        }
    }

    if !high.is_empty() {
        high.sort();
        high.dedup();
        findings.push(Finding {
            confidence: Confidence::High,
            category: "packet_relay_correlation".to_string(),
            title:
                "Packet capture confirms a local relay is duplicating Minecraft upstream traffic"
                    .to_string(),
            details: high,
        });
    } else if !medium.is_empty() {
        medium.sort();
        medium.dedup();
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "packet_relay_correlation".to_string(),
            title: "Packet capture shows overlapping duplicate Minecraft upstream conversations"
                .to_string(),
            details: medium,
        });
    }
}

pub(super) fn detect_private_peer_packet_proxy(
    findings: &mut Vec<Finding>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    packet_capture_analysis: Option<&PacketCaptureAnalysis>,
) {
    let Some(analysis) = packet_capture_analysis else {
        return;
    };

    let client_flows = active_minecraft_connections(netstat_entries, process_map, minecraft_ports);
    if client_flows.is_empty() {
        return;
    }

    let mut high = Vec::new();

    for flow in client_flows {
        let Some(process) = process_map.get(&flow.pid) else {
            continue;
        };
        let Some(stat) = find_packet_tuple_stat(
            Some(analysis),
            flow.pid,
            &flow.local_addr,
            flow.local_port,
            &flow.remote_addr,
            flow.remote_port,
        ) else {
            continue;
        };
        let Some(handshake_host_raw) = stat.minecraft_handshake_host.as_ref() else {
            continue;
        };

        let handshake_host = normalize_ip_literal(handshake_host_raw);
        let handshake_port = stat.minecraft_handshake_port.unwrap_or(flow.remote_port);
        let same_host = handshake_target_matches_remote(&handshake_host, &flow.remote_addr);
        if same_host && handshake_port == flow.remote_port {
            continue;
        }
        if !packet_tuple_has_bidirectional_payload(stat) || packet_tuple_total_packets(stat) < 4 {
            continue;
        }

        let public_or_domain_target = parse_ip_addr_literal(&handshake_host)
            .is_some_and(|_| !is_lan_ip(&handshake_host) && !is_loopback_ip(&handshake_host))
            || (parse_ip_addr_literal(&handshake_host).is_none()
                && handshake_host.contains('.')
                && !handshake_host.eq_ignore_ascii_case("localhost"));
        let inbound_windowsish = stat.ttl_in_values.iter().any(|ttl| *ttl >= 120);
        if !public_or_domain_target || !inbound_windowsish {
            continue;
        }

        high.push(format!(
            "PID {} {} | private_peer={}:{} | handshake_target={}:{} | ttl_in={:?} | packets={}",
            flow.pid,
            process.name,
            flow.remote_addr,
            flow.remote_port,
            handshake_host_raw,
            handshake_port,
            stat.ttl_in_values,
            packet_activity_for_tuple(
                Some(analysis),
                flow.pid,
                &flow.local_addr,
                flow.local_port,
                &flow.remote_addr,
                flow.remote_port
            )
            .unwrap_or_else(|| "none".to_string())
        ));
    }

    if !high.is_empty() {
        high.sort();
        high.dedup();
        findings.push(Finding {
            confidence: Confidence::High,
            category: "private_peer_packet_proxy".to_string(),
            title: "Minecraft packets indicate a private peer is relaying traffic to a different target".to_string(),
            details: high,
        });
    }
}

pub(super) fn detect_minecraft_handshake_target_mismatch(
    findings: &mut Vec<Finding>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    packet_capture_analysis: Option<&PacketCaptureAnalysis>,
) {
    let Some(analysis) = packet_capture_analysis else {
        return;
    };

    let client_flows = active_minecraft_connections(netstat_entries, process_map, minecraft_ports);
    if client_flows.is_empty() {
        return;
    }

    let mut high = Vec::new();
    let mut medium = Vec::new();
    for flow in client_flows {
        let Some(process) = process_map.get(&flow.pid) else {
            continue;
        };
        let Some(stat) = find_packet_tuple_stat(
            Some(analysis),
            flow.pid,
            &flow.local_addr,
            flow.local_port,
            &flow.remote_addr,
            flow.remote_port,
        ) else {
            continue;
        };
        let Some(handshake_host_raw) = stat.minecraft_handshake_host.as_ref() else {
            continue;
        };

        let handshake_host = normalize_ip_literal(handshake_host_raw);
        let handshake_port = stat.minecraft_handshake_port.unwrap_or(flow.remote_port);
        let same_host = handshake_target_matches_remote(&handshake_host, &flow.remote_addr);
        let port_mismatch = handshake_port != flow.remote_port;
        let handshake_is_public_ip = parse_ip_addr_literal(&handshake_host)
            .is_some_and(|_| !is_lan_ip(&handshake_host) && !is_loopback_ip(&handshake_host));
        let handshake_is_domain = parse_ip_addr_literal(&handshake_host).is_none()
            && handshake_host.contains('.')
            && !handshake_host.eq_ignore_ascii_case("localhost");
        if same_host && !port_mismatch {
            continue;
        }

        let detail = format!(
            "PID {} {} | tcp_remote={}:{} | handshake_target={}:{} | protocol={:?} state={:?} | tuple_packets={}",
            flow.pid,
            process.name,
            flow.remote_addr,
            flow.remote_port,
            handshake_host_raw,
            handshake_port,
            stat.minecraft_handshake_protocol,
            stat.minecraft_handshake_state,
            packet_activity_for_tuple(
                Some(analysis),
                flow.pid,
                &flow.local_addr,
                flow.local_port,
                &flow.remote_addr,
                flow.remote_port
            )
            .unwrap_or_else(|| "none".to_string())
        );

        if port_mismatch || handshake_is_public_ip {
            high.push(format!(
                "Minecraft handshake target differs from the private relay endpoint in a way normal direct LAN play should not: {detail}"
            ));
        } else if handshake_is_domain && !same_host {
            medium.push(format!(
                "Minecraft handshake advertises a different hostname than the private relay endpoint: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "minecraft_handshake_mismatch".to_string(),
            title: "Minecraft packet handshake points to a different target than the active private endpoint".to_string(),
            details: high,
        });
    } else if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "minecraft_handshake_mismatch".to_string(),
            title: "Minecraft packet handshake differs from the private endpoint".to_string(),
            details: medium,
        });
    }
}

fn packet_tuple_total_packets(stat: &PacketTupleStat) -> u64 {
    stat.outbound_packets + stat.inbound_packets
}

fn packet_tuple_has_bidirectional_payload(stat: &PacketTupleStat) -> bool {
    stat.outbound_packets > 0
        && stat.inbound_packets > 0
        && (stat.outbound_payload_bytes > 0 || stat.inbound_payload_bytes > 0)
}

fn packet_tuple_windows_overlap(a: &PacketTupleStat, b: &PacketTupleStat) -> bool {
    let (Some(a_start), Some(a_end), Some(b_start), Some(b_end)) =
        (a.first_time, a.last_time, b.first_time, b.last_time)
    else {
        return false;
    };
    let latest_start = a_start.max(b_start);
    let earliest_end = a_end.min(b_end);
    earliest_end + 0.25 >= latest_start
}

fn packet_similarity_ratio(left: u64, right: u64) -> f64 {
    if left == 0 || right == 0 {
        return 0.0;
    }
    let smaller = left.min(right) as f64;
    let larger = left.max(right) as f64;
    smaller / larger
}

fn packet_handshake_signature(stat: &PacketTupleStat) -> Option<String> {
    let host = stat.minecraft_handshake_host.as_ref()?;
    let port = stat.minecraft_handshake_port?;
    Some(format!(
        "{}:{}:{:?}:{:?}",
        normalize_ip_literal(host),
        port,
        stat.minecraft_handshake_protocol,
        stat.minecraft_handshake_state
    ))
}
