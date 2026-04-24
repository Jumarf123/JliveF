use super::*;
use pcap_file::DataLink;
use pcap_file::pcapng::{Block, PcapNgReader};
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PacketCaptureAnalysis {
    pub(crate) total_packets: u64,
    pub(crate) tuples: Vec<PacketTupleStat>,
    pub(crate) endpoints: Vec<PacketEndpointStat>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PacketTupleStat {
    pub(crate) id: String,
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) local_addr: String,
    pub(crate) local_port: u16,
    pub(crate) remote_addr: String,
    pub(crate) remote_port: u16,
    pub(crate) outbound_packets: u64,
    pub(crate) inbound_packets: u64,
    pub(crate) outbound_payload_bytes: u64,
    pub(crate) inbound_payload_bytes: u64,
    pub(crate) syn_out: u64,
    pub(crate) syn_in: u64,
    pub(crate) fin_out: u64,
    pub(crate) fin_in: u64,
    pub(crate) rst_out: u64,
    pub(crate) rst_in: u64,
    pub(crate) ack_out: u64,
    pub(crate) ack_in: u64,
    pub(crate) ttl_in_values: Vec<u16>,
    pub(crate) ttl_out_values: Vec<u16>,
    pub(crate) first_time: Option<f64>,
    pub(crate) last_time: Option<f64>,
    pub(crate) duration: f64,
    pub(crate) minecraft_handshake_host: Option<String>,
    pub(crate) minecraft_handshake_port: Option<u16>,
    pub(crate) minecraft_handshake_protocol: Option<u32>,
    pub(crate) minecraft_handshake_state: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PacketEndpointStat {
    pub(crate) remote_endpoint: String,
    pub(crate) packets: u64,
    pub(crate) tuple_ids: Vec<String>,
}

#[derive(Clone, Debug)]
struct PacketTupleRequest {
    id: String,
    pid: u32,
    process_name: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
}

struct ParsedPacket<'a> {
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
    ttl: u16,
    payload: &'a [u8],
}

pub(super) fn analyze_pktmon_capture(
    raw_commands: &mut Vec<CommandArtifact>,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    etl_path: &Path,
    pcap_path: &Path,
    started_by_us: bool,
) -> Option<PacketCaptureAnalysis> {
    if !started_by_us || !etl_path.exists() {
        return None;
    }

    let tuple_requests = build_packet_tuple_requests(process_map, netstat_entries, minecraft_ports);
    if tuple_requests.is_empty() {
        raw_commands.push(CommandArtifact {
            name: "pktmon_packet_analysis".to_string(),
            command: "embedded Rust packet analysis".to_string(),
            output: "No relevant Minecraft/proxy tuples were eligible for packet correlation."
                .to_string(),
        });
        return None;
    }

    let convert_args_owned = vec![
        "etl2pcap".to_string(),
        etl_path.display().to_string(),
        "--out".to_string(),
        pcap_path.display().to_string(),
    ];
    let convert_args = convert_args_owned
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let convert_command = format!("pktmon {}", convert_args_owned.join(" "));
    let convert_output = sanitize_command_output(
        "pktmon_etl2pcap_runtime",
        "pktmon",
        run_command_uncached("pktmon", &convert_args)
            .unwrap_or_else(|| format!("Failed to run {convert_command}")),
    );
    raw_commands.push(CommandArtifact {
        name: "pktmon_etl2pcap_runtime".to_string(),
        command: convert_command,
        output: convert_output,
    });
    if !pcap_path.exists() {
        return None;
    }

    match parse_pktmon_pcapng(pcap_path, &tuple_requests) {
        Ok(analysis) => {
            let capture_root = etl_path.parent()?;
            let analysis_json_path = capture_root.join("packet_analysis.json");
            let _ = fs::write(
                &analysis_json_path,
                serde_json::to_string_pretty(&analysis).unwrap_or_default(),
            );
            raw_commands.push(CommandArtifact {
                name: "pktmon_packet_parser".to_string(),
                command: "embedded Rust pcapng parser".to_string(),
                output: format!(
                    "Parsed {} packets across {} monitored tuples.",
                    analysis.total_packets,
                    analysis.tuples.len()
                ),
            });
            raw_commands.push(CommandArtifact {
                name: "pktmon_packet_parser_summary".to_string(),
                command: "pktmon packet parser summary".to_string(),
                output: format!(
                    "total_packets={}\nmonitored_tuples={}\nactive_endpoints={}",
                    analysis.total_packets,
                    analysis.tuples.len(),
                    analysis.endpoints.len()
                ),
            });
            Some(analysis)
        }
        Err(error) => {
            raw_commands.push(CommandArtifact {
                name: "pktmon_packet_parser".to_string(),
                command: "embedded Rust pcapng parser".to_string(),
                output: format!("Embedded packet parser failed: {error:#}"),
            });
            None
        }
    }
}

pub(super) fn packet_activity_for_tuple(
    analysis: Option<&PacketCaptureAnalysis>,
    pid: u32,
    local_addr: &str,
    local_port: u16,
    remote_addr: &str,
    remote_port: u16,
) -> Option<String> {
    let stat = find_packet_tuple_stat(
        analysis,
        pid,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    )?;
    let total_packets = stat.outbound_packets + stat.inbound_packets;
    if total_packets == 0 {
        return None;
    }
    Some(format!(
        "{} packets (out={}, in={}, payload_out={}, payload_in={}, ttl_in={:?}, ttl_out={:?}, duration={:.3}s)",
        total_packets,
        stat.outbound_packets,
        stat.inbound_packets,
        stat.outbound_payload_bytes,
        stat.inbound_payload_bytes,
        stat.ttl_in_values,
        stat.ttl_out_values,
        stat.duration
    ))
}

pub(super) fn find_packet_tuple_stat<'a>(
    analysis: Option<&'a PacketCaptureAnalysis>,
    pid: u32,
    local_addr: &str,
    local_port: u16,
    remote_addr: &str,
    remote_port: u16,
) -> Option<&'a PacketTupleStat> {
    let analysis = analysis?;
    let normalized_local = normalize_ip_literal(local_addr);
    let normalized_remote = normalize_ip_literal(remote_addr);
    analysis
        .tuples
        .iter()
        .find(|item| {
            item.pid == pid
                && item.local_port == local_port
                && item.remote_port == remote_port
                && item.local_addr.eq_ignore_ascii_case(&normalized_local)
                && item.remote_addr.eq_ignore_ascii_case(&normalized_remote)
        })
        .or_else(|| {
            analysis.tuples.iter().find(|item| {
                item.local_port == local_port
                    && item.remote_port == remote_port
                    && item.local_addr.eq_ignore_ascii_case(&normalized_local)
                    && item.remote_addr.eq_ignore_ascii_case(&normalized_remote)
            })
        })
}

fn build_packet_tuple_requests(
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
) -> Vec<PacketTupleRequest> {
    let client_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if client_flows.is_empty() {
        return Vec::new();
    }

    let remote_endpoints = client_flows
        .iter()
        .map(|flow| (flow.remote_addr.clone(), flow.remote_port))
        .collect::<HashSet<_>>();
    let listener_ports = netstat_entries
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

    let mut seen = HashSet::new();
    let mut requests = Vec::new();

    let mut push_request = |entry: &NetstatTcp| {
        let Some(process) = process_map.get(&entry.pid) else {
            return;
        };
        let key = format!(
            "{}|{}|{}|{}|{}",
            entry.pid, entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
        );
        if !seen.insert(key) {
            return;
        }
        requests.push(PacketTupleRequest {
            id: format!(
                "{}:{}:{}->{}:{}",
                entry.pid, entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
            ),
            pid: entry.pid,
            process_name: process.name.clone(),
            local_addr: entry.local_addr.clone(),
            local_port: entry.local_port,
            remote_addr: entry.remote_addr.clone(),
            remote_port: entry.remote_port,
        });
    };

    for flow in &client_flows {
        push_request(flow);
    }

    for entry in netstat_entries {
        if !matches!(
            entry.state.to_ascii_uppercase().as_str(),
            "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
        ) {
            continue;
        }
        if entry.remote_port == 0
            || is_wildcard_ip(&entry.remote_addr)
            || is_loopback_ip(&entry.remote_addr)
            || !remote_endpoints.contains(&(entry.remote_addr.clone(), entry.remote_port))
        {
            continue;
        }

        let has_listener = listener_ports
            .get(&entry.pid)
            .is_some_and(|ports| !ports.is_empty());
        let has_loopback_session = netstat_entries.iter().any(|loopback| {
            loopback.pid == entry.pid
                && matches!(
                    loopback.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                )
                && is_loopback_ip(&loopback.local_addr)
                && is_loopback_ip(&loopback.remote_addr)
                && listener_ports.get(&entry.pid).is_some_and(|ports| {
                    ports.contains(&loopback.local_port) || ports.contains(&loopback.remote_port)
                })
        });
        if has_listener || has_loopback_session {
            push_request(entry);
        }
    }

    requests.sort_by(|a, b| {
        a.pid
            .cmp(&b.pid)
            .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            .then_with(|| a.remote_port.cmp(&b.remote_port))
            .then_with(|| a.local_port.cmp(&b.local_port))
    });
    requests
}

fn parse_pktmon_pcapng(
    pcap_path: &Path,
    tuple_requests: &[PacketTupleRequest],
) -> Result<PacketCaptureAnalysis> {
    let file = File::open(pcap_path)
        .with_context(|| format!("failed to open packet capture {}", pcap_path.display()))?;
    let mut reader =
        PcapNgReader::new(file).with_context(|| "failed to open pcapng reader".to_string())?;

    let mut stats = HashMap::<String, PacketTupleStat>::new();
    let mut reverse_map = HashMap::<(String, u16, String, u16), String>::new();
    let mut seq_bases = HashMap::<String, u32>::new();
    let mut seq_segments = HashMap::<String, HashMap<u32, Vec<u8>>>::new();

    for item in tuple_requests {
        let key = canonical_tuple_key(
            &item.local_addr,
            item.local_port,
            &item.remote_addr,
            item.remote_port,
        );
        stats.insert(
            key.clone(),
            PacketTupleStat {
                id: item.id.clone(),
                pid: item.pid,
                process_name: item.process_name.clone(),
                local_addr: normalize_ip_literal(&item.local_addr),
                local_port: item.local_port,
                remote_addr: normalize_ip_literal(&item.remote_addr),
                remote_port: item.remote_port,
                outbound_packets: 0,
                inbound_packets: 0,
                outbound_payload_bytes: 0,
                inbound_payload_bytes: 0,
                syn_out: 0,
                syn_in: 0,
                fin_out: 0,
                fin_in: 0,
                rst_out: 0,
                rst_in: 0,
                ack_out: 0,
                ack_in: 0,
                ttl_in_values: Vec::new(),
                ttl_out_values: Vec::new(),
                first_time: None,
                last_time: None,
                duration: 0.0,
                minecraft_handshake_host: None,
                minecraft_handshake_port: None,
                minecraft_handshake_protocol: None,
                minecraft_handshake_state: None,
            },
        );
        reverse_map.insert(
            (
                normalize_ip_literal(&item.remote_addr),
                item.remote_port,
                normalize_ip_literal(&item.local_addr),
                item.local_port,
            ),
            key.clone(),
        );
        seq_segments.insert(key, HashMap::new());
    }

    let mut endpoint_activity = HashMap::<String, (u64, HashSet<String>)>::new();
    let mut total_packets = 0u64;

    while let Some(block) = reader.next_block() {
        let block = block.with_context(|| "failed to read pcapng block".to_string())?;
        let Block::EnhancedPacket(packet) = block else {
            continue;
        };
        let packet = packet.into_owned();
        let linktype = reader
            .interfaces()
            .get(packet.interface_id as usize)
            .map(|iface| iface.linktype)
            .unwrap_or(DataLink::ETHERNET);
        let Some(parsed) = parse_packet_data(packet.data.as_ref(), linktype) else {
            continue;
        };
        let timestamp = packet.timestamp.as_secs_f64();
        let direct_key = canonical_tuple_key(&parsed.src, parsed.sport, &parsed.dst, parsed.dport);
        let (matched_key, direction) = if stats.contains_key(&direct_key) {
            (direct_key, PacketDirection::Outbound)
        } else if let Some(reverse_key) = reverse_map.get(&(
            parsed.src.clone(),
            parsed.sport,
            parsed.dst.clone(),
            parsed.dport,
        )) {
            (reverse_key.clone(), PacketDirection::Inbound)
        } else {
            continue;
        };

        total_packets += 1;
        let Some(item) = stats.get_mut(&matched_key) else {
            continue;
        };
        let endpoint_key = format!("{}:{}", item.remote_addr, item.remote_port);
        let endpoint_entry = endpoint_activity
            .entry(endpoint_key)
            .or_insert_with(|| (0, HashSet::new()));
        endpoint_entry.0 += 1;
        endpoint_entry.1.insert(item.id.clone());

        update_timestamp_bounds(item, timestamp);
        update_packet_counters(item, &parsed, direction);

        if matches!(direction, PacketDirection::Outbound) && !parsed.payload.is_empty() {
            let entry = seq_segments.entry(matched_key.clone()).or_default();
            let payload = parsed.payload.to_vec();
            let seq = parsed.seq;
            if seq_bases
                .get(&matched_key)
                .is_none_or(|current| seq < *current)
            {
                seq_bases.insert(matched_key.clone(), seq);
            }
            let replace = entry
                .get(&seq)
                .is_none_or(|current| payload.len() > current.len());
            if replace {
                entry.insert(seq, payload);
            }
        }
    }

    let mut tuples = stats.into_values().collect::<Vec<_>>();
    tuples.sort_by(|a, b| a.id.cmp(&b.id));
    for item in &mut tuples {
        dedup_u16_vec(&mut item.ttl_in_values);
        dedup_u16_vec(&mut item.ttl_out_values);
        if let (Some(first), Some(last)) = (item.first_time, item.last_time) {
            item.duration = (last - first).max(0.0);
        }

        let key = canonical_tuple_key(
            &item.local_addr,
            item.local_port,
            &item.remote_addr,
            item.remote_port,
        );
        let prefix = build_contiguous_prefix(
            seq_segments.get(&key).cloned().unwrap_or_default(),
            seq_bases.get(&key).copied(),
            512,
        );
        if let Some(handshake) = try_parse_minecraft_handshake(&prefix) {
            item.minecraft_handshake_host = Some(handshake.host);
            item.minecraft_handshake_port = Some(handshake.port);
            item.minecraft_handshake_protocol = Some(handshake.protocol_version);
            item.minecraft_handshake_state = Some(handshake.next_state);
        }
    }

    let mut endpoints = endpoint_activity
        .into_iter()
        .map(
            |(remote_endpoint, (packets, tuple_ids))| PacketEndpointStat {
                remote_endpoint,
                packets,
                tuple_ids: {
                    let mut items = tuple_ids.into_iter().collect::<Vec<_>>();
                    items.sort();
                    items
                },
            },
        )
        .collect::<Vec<_>>();
    endpoints.sort_by(|a, b| a.remote_endpoint.cmp(&b.remote_endpoint));

    Ok(PacketCaptureAnalysis {
        total_packets,
        tuples,
        endpoints,
    })
}

fn canonical_tuple_key(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
) -> String {
    format!(
        "{}:{}->{}:{}",
        normalize_ip_literal(local_ip),
        local_port,
        normalize_ip_literal(remote_ip),
        remote_port
    )
}

fn parse_packet_data<'a>(data: &'a [u8], linktype: DataLink) -> Option<ParsedPacket<'a>> {
    match linktype {
        DataLink::ETHERNET | DataLink::EXP_ETHERNET => parse_ethernet_frame(data),
        DataLink::RAW => parse_ip_packet(data),
        DataLink::NULL | DataLink::LOOP => parse_loopback_frame(data),
        DataLink::LINUX_SLL => parse_linux_sll_frame(data),
        _ => parse_ip_packet(data)
            .or_else(|| parse_ethernet_frame(data))
            .or_else(|| parse_linux_sll_frame(data))
            .or_else(|| parse_loopback_frame(data)),
    }
}

fn parse_ethernet_frame(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut offset = 14usize;
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    while matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) {
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }
    let payload = data.get(offset..)?;
    match ethertype {
        0x0800 | 0x86DD => parse_ip_packet(payload),
        _ => None,
    }
}

fn parse_linux_sll_frame(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 16 {
        return None;
    }
    let protocol = u16::from_be_bytes([data[14], data[15]]);
    let payload = data.get(16..)?;
    match protocol {
        0x0800 | 0x86DD => parse_ip_packet(payload),
        _ => None,
    }
}

fn parse_loopback_frame(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 4 {
        return None;
    }
    let family_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let family_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let payload = data.get(4..)?;
    match (family_le, family_be) {
        (2, _) | (_, 2) => parse_ipv4_packet(payload),
        (10 | 23 | 24 | 28 | 30, _) | (_, 10 | 23 | 24 | 28 | 30) => parse_ipv6_packet(payload),
        _ => parse_ip_packet(payload),
    }
}

fn parse_ip_packet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    match data.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4_packet(data),
        Some(6) => parse_ipv6_packet(data),
        _ => None,
    }
}

fn parse_ipv4_packet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 20 {
        return None;
    }
    let ihl = usize::from(data[0] & 0x0F) * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    if data[9] != 6 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    let ttl = u16::from(data[8]);
    let packet_end = if total_len >= ihl && total_len <= data.len() {
        total_len
    } else {
        data.len()
    };
    let payload = data.get(ihl..packet_end)?;
    let src = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    parse_tcp_segment(payload, src, dst, ttl)
}

fn parse_ipv6_packet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
    let mut next_header = data[6];
    let ttl = u16::from(data[7]);
    let src = format_ipv6_addr(data.get(8..24)?);
    let dst = format_ipv6_addr(data.get(24..40)?);
    let mut offset = 40usize;
    let packet_end = data.len().min(40usize.saturating_add(payload_len));

    loop {
        match next_header {
            6 => {
                let payload = data.get(offset..packet_end)?;
                return parse_tcp_segment(payload, src, dst, ttl);
            }
            0 | 43 | 60 => {
                let header = data.get(offset..offset + 8)?;
                next_header = header[0];
                let ext_len = (usize::from(header[1]) + 1) * 8;
                offset = offset.checked_add(ext_len)?;
            }
            44 => {
                let header = data.get(offset..offset + 8)?;
                let fragment_offset = ((u16::from(header[2]) << 8) | u16::from(header[3])) & 0xfff8;
                if fragment_offset != 0 {
                    return None;
                }
                next_header = header[0];
                offset = offset.checked_add(8)?;
            }
            51 => {
                let header = data.get(offset..offset + 8)?;
                next_header = header[0];
                let ext_len = (usize::from(header[1]) + 2) * 4;
                offset = offset.checked_add(ext_len)?;
            }
            _ => return None,
        }
        if offset >= packet_end {
            return None;
        }
    }
}

fn format_ipv6_addr(bytes: &[u8]) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&bytes[..16]);
    std::net::Ipv6Addr::from(octets).to_string()
}

fn parse_tcp_segment<'a>(
    data: &'a [u8],
    src: String,
    dst: String,
    ttl: u16,
) -> Option<ParsedPacket<'a>> {
    if data.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let offset = usize::from(data[12] >> 4) * 4;
    if offset < 20 || data.len() < offset {
        return None;
    }
    Some(ParsedPacket {
        src,
        dst,
        sport,
        dport,
        seq,
        flags: data[13],
        ttl,
        payload: &data[offset..],
    })
}

fn update_timestamp_bounds(item: &mut PacketTupleStat, timestamp: f64) {
    item.first_time = match item.first_time {
        Some(current) => Some(current.min(timestamp)),
        None => Some(timestamp),
    };
    item.last_time = match item.last_time {
        Some(current) => Some(current.max(timestamp)),
        None => Some(timestamp),
    };
}

fn update_packet_counters(
    item: &mut PacketTupleStat,
    parsed: &ParsedPacket<'_>,
    direction: PacketDirection,
) {
    let syn = parsed.flags & 0x02 != 0;
    let ack = parsed.flags & 0x10 != 0;
    let fin = parsed.flags & 0x01 != 0;
    let rst = parsed.flags & 0x04 != 0;
    let payload_len = parsed.payload.len() as u64;

    match direction {
        PacketDirection::Outbound => {
            item.outbound_packets += 1;
            item.outbound_payload_bytes += payload_len;
            item.ttl_out_values.push(parsed.ttl);
            if syn {
                item.syn_out += 1;
            }
            if ack {
                item.ack_out += 1;
            }
            if fin {
                item.fin_out += 1;
            }
            if rst {
                item.rst_out += 1;
            }
        }
        PacketDirection::Inbound => {
            item.inbound_packets += 1;
            item.inbound_payload_bytes += payload_len;
            item.ttl_in_values.push(parsed.ttl);
            if syn {
                item.syn_in += 1;
            }
            if ack {
                item.ack_in += 1;
            }
            if fin {
                item.fin_in += 1;
            }
            if rst {
                item.rst_in += 1;
            }
        }
    }
}

fn dedup_u16_vec(values: &mut Vec<u16>) {
    values.sort_unstable();
    values.dedup();
    if values.len() > 16 {
        values.truncate(16);
    }
}

fn build_contiguous_prefix(
    segments: HashMap<u32, Vec<u8>>,
    base_seq: Option<u32>,
    limit: usize,
) -> Vec<u8> {
    let Some(mut next_seq) = base_seq else {
        return Vec::new();
    };
    if segments.is_empty() {
        return Vec::new();
    }

    let mut ordered = segments.into_iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(seq, _)| *seq);

    let mut prefix = Vec::new();
    while prefix.len() < limit {
        if let Some((_, data)) = ordered.iter().find(|(seq, _)| *seq == next_seq) {
            let take = (limit - prefix.len()).min(data.len());
            prefix.extend_from_slice(&data[..take]);
            next_seq = next_seq.saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
            continue;
        }

        let mut overlap = None;
        for (seq, data) in &ordered {
            if *seq < next_seq {
                let end = seq.saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
                if next_seq < end {
                    if let Ok(start) = usize::try_from(next_seq - *seq) {
                        overlap = Some(&data[start..]);
                    }
                    break;
                }
            }
        }
        let Some(data) = overlap else {
            break;
        };
        let take = (limit - prefix.len()).min(data.len());
        prefix.extend_from_slice(&data[..take]);
        next_seq = next_seq.saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
    }

    prefix
}

struct MinecraftHandshake {
    protocol_version: u32,
    host: String,
    port: u16,
    next_state: u32,
}

fn try_parse_minecraft_handshake(buf: &[u8]) -> Option<MinecraftHandshake> {
    let (packet_length, mut offset) = read_varint(buf, 0)?;
    if packet_length == 0 {
        return None;
    }
    let available = buf.len().saturating_sub(offset);
    let _effective_len = packet_length.min(u32::try_from(available).ok()?);

    let (packet_id, next_offset) = read_varint(buf, offset)?;
    offset = next_offset;
    if packet_id != 0 {
        return None;
    }

    let (protocol_version, next_offset) = read_varint(buf, offset)?;
    offset = next_offset;

    let (host_len, next_offset) = read_varint(buf, offset)?;
    offset = next_offset;
    let host_len = usize::try_from(host_len).ok()?;
    if host_len == 0 || host_len > 255 || offset.checked_add(host_len + 2)? > buf.len() {
        return None;
    }
    let host = String::from_utf8_lossy(buf.get(offset..offset + host_len)?)
        .trim()
        .to_string();
    if host.is_empty() {
        return None;
    }
    offset += host_len;
    let port = u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]);
    offset += 2;

    let (next_state, _) = read_varint(buf, offset)?;
    if !(1..=3).contains(&next_state) {
        return None;
    }

    Some(MinecraftHandshake {
        protocol_version,
        host,
        port,
        next_state,
    })
}

fn read_varint(buf: &[u8], mut offset: usize) -> Option<(u32, usize)> {
    let mut num_read = 0u32;
    let mut result = 0u32;
    loop {
        let value = *buf.get(offset)?;
        offset += 1;
        result |= u32::from(value & 0x7f) << (7 * num_read);
        num_read += 1;
        if value & 0x80 == 0 {
            return Some((result, offset));
        }
        if num_read >= 5 {
            return None;
        }
    }
}

#[derive(Copy, Clone)]
enum PacketDirection {
    Outbound,
    Inbound,
}
