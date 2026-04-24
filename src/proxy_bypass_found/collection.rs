use super::*;

pub(super) fn collect_command(
    raw_commands: &mut Vec<CommandArtifact>,
    name: &str,
    exe: &str,
    args: &[&str],
) -> String {
    let command = format!("{exe} {}", args.join(" "));
    let output = sanitize_command_output(
        name,
        exe,
        run_command(exe, args).unwrap_or_else(|| format!("Failed to run {command}")),
    );
    raw_commands.push(CommandArtifact {
        name: name.to_string(),
        command,
        output: output.clone(),
    });
    output
}

pub(super) fn collect_fresh_command(
    raw_commands: &mut Vec<CommandArtifact>,
    name: &str,
    exe: &str,
    args: &[&str],
) -> String {
    let command = format!("{exe} {}", args.join(" "));
    let output = sanitize_command_output(
        name,
        exe,
        run_command_uncached(exe, args).unwrap_or_else(|| format!("Failed to run {command}")),
    );
    raw_commands.push(CommandArtifact {
        name: name.to_string(),
        command,
        output: output.clone(),
    });
    output
}

pub(super) fn collect_commands_parallel(
    raw_commands: &mut Vec<CommandArtifact>,
    specs: &[ParallelCommandSpec],
) -> HashMap<String, String> {
    let mut artifacts = specs
        .par_iter()
        .map(|spec| {
            let command = format!("{} {}", spec.exe, spec.args.join(" "));
            let output = sanitize_command_output(
                spec.name,
                spec.exe,
                run_command_uncached(spec.exe, spec.args)
                    .unwrap_or_else(|| format!("Failed to run {command}")),
            );
            CommandArtifact {
                name: spec.name.to_string(),
                command,
                output,
            }
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));

    let mut outputs = HashMap::new();
    for artifact in artifacts {
        outputs.insert(artifact.name.clone(), artifact.output.clone());
        raw_commands.push(artifact);
    }
    outputs
}

pub(super) fn sanitize_command_output(name: &str, exe: &str, output: String) -> String {
    if exe.eq_ignore_ascii_case("nbtstat") || name.starts_with("nbtstat_") {
        sanitize_nbtstat_output(&output)
    } else {
        output
    }
}

pub(super) fn sanitize_nbtstat_output(text: &str) -> String {
    let zero_ip_block_re = Regex::new(
        r"(?ims)(?:^\s*[^\r\n]*:\s*\r?\n)?\s*Node IpAddress:\s*\[0\.0\.0\.0\][^\r\n]*\r?\n(?:\s*\r?\n)?\s*(?:Host not found\.|Узел не найден\.|Не удалось найти узел\.)\s*(?:\r?\n)+",
    )
    .unwrap();
    let normalized = zero_ip_block_re
        .replace_all(text, "")
        .to_string()
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\r' | '\n' | '\t'))
        .collect::<String>()
        .replace("\r\n", "\n");
    let mut kept = Vec::new();

    for chunk in normalized.split("\n\n") {
        let trimmed = chunk.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();
        let useless_zero_addr = trimmed.contains("0.0.0.0")
            && (lower.contains("node ipaddress")
                || lower.contains("node ip address")
                || lower.contains("ip-адрес узла"));
        let host_not_found = lower.contains("host not found")
            || lower.contains("узел не найден")
            || lower.contains("не удается найти")
            || lower.contains("не удалось найти");
        if useless_zero_addr && host_not_found {
            continue;
        }
        kept.push(trimmed.to_string());
    }

    if kept.is_empty() {
        text.trim().to_string()
    } else {
        kept.join("\r\n\r\n")
    }
}

pub(super) fn ping_private_gateways(
    raw_commands: &mut Vec<CommandArtifact>,
    adapters: &[AdapterBlock],
) {
    let mut seen = HashSet::new();
    for gateway in adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .filter(|gateway| is_private_ipv4(gateway))
    {
        if !seen.insert(gateway.clone()) {
            continue;
        }
        collect_fresh_command(
            raw_commands,
            &format!("ping_gateway_{}", gateway.replace('.', "_")),
            "ping",
            &["-n", "1", "-w", "300", gateway],
        );
    }
}

pub(super) fn probe_private_gateways_tcp(
    raw_commands: &mut Vec<CommandArtifact>,
    adapters: &[AdapterBlock],
    probe_ports: &[u16],
) {
    let mut seen = HashSet::new();
    for gateway in adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .filter(|gateway| is_private_ipv4(gateway))
    {
        if !seen.insert(gateway.clone()) {
            continue;
        }
        for port in probe_ports
            .iter()
            .chain(WINDOWS_HOST_PROBE_PORTS.iter())
            .copied()
        {
            let command = format!("tcp_probe remote={gateway}:{port}");
            let name = format!("tcp_probe_gateway_{}_{}", gateway.replace('.', "_"), port);
            let output = probe_tcp_port(gateway, port, 120);
            raw_commands.push(CommandArtifact {
                name,
                command,
                output,
            });
        }
    }
}

pub(super) fn probe_private_gateways_nbtstat(
    raw_commands: &mut Vec<CommandArtifact>,
    adapters: &[AdapterBlock],
) {
    let mut seen = HashSet::new();
    for gateway in adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .filter(|gateway| is_private_ipv4(gateway))
    {
        if !seen.insert(gateway.clone()) {
            continue;
        }
        collect_fresh_command(
            raw_commands,
            &format!("nbtstat_gateway_{}", gateway.replace('.', "_")),
            "nbtstat",
            &["-A", gateway],
        );
    }
}

pub(super) fn ping_private_minecraft_peers(
    raw_commands: &mut Vec<CommandArtifact>,
    active_minecraft: &[NetstatTcp],
) {
    let mut seen = HashSet::new();
    for peer in active_minecraft
        .iter()
        .map(|connection| connection.remote_addr.as_str())
        .filter(|peer| is_private_ipv4(peer))
    {
        if !seen.insert(peer.to_string()) {
            continue;
        }
        collect_fresh_command(
            raw_commands,
            &format!("ping_minecraft_peer_{}", peer.replace('.', "_")),
            "ping",
            &["-n", "1", "-w", "250", peer],
        );
    }
}

pub(super) fn probe_private_minecraft_peers_tcp(
    raw_commands: &mut Vec<CommandArtifact>,
    active_minecraft: &[NetstatTcp],
    probe_ports: &[u16],
) {
    let mut seen = HashSet::new();
    for peer in active_minecraft
        .iter()
        .map(|connection| connection.remote_addr.as_str())
        .filter(|peer| is_private_ipv4(peer))
    {
        if !seen.insert(peer.to_string()) {
            continue;
        }
        for port in probe_ports
            .iter()
            .chain(WINDOWS_HOST_PROBE_PORTS.iter())
            .copied()
        {
            let command = format!("tcp_probe_peer remote={peer}:{port}");
            let name = format!("tcp_probe_peer_{}_{}", peer.replace('.', "_"), port);
            let output = probe_tcp_port(peer, port, 120);
            raw_commands.push(CommandArtifact {
                name,
                command,
                output,
            });
        }
    }
}

pub(super) fn probe_private_minecraft_peers_nbtstat(
    raw_commands: &mut Vec<CommandArtifact>,
    active_minecraft: &[NetstatTcp],
) {
    let mut seen = HashSet::new();
    for peer in active_minecraft
        .iter()
        .map(|connection| connection.remote_addr.as_str())
        .filter(|peer| is_private_ipv4(peer))
    {
        if !seen.insert(peer.to_string()) {
            continue;
        }
        collect_fresh_command(
            raw_commands,
            &format!("nbtstat_peer_{}", peer.replace('.', "_")),
            "nbtstat",
            &["-A", peer],
        );
    }
}

pub(super) fn probe_tcp_port(ip: &str, port: u16, timeout_ms: u64) -> String {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return "invalid ip".to_string();
    };
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
        Ok(_) => "open".to_string(),
        Err(error) => format!("closed: {error}"),
    }
}

pub(super) fn perform_udp_proxy_probes(
    raw_commands: &mut Vec<CommandArtifact>,
    adapters: &[AdapterBlock],
    probe_ports: &[u16],
) {
    let mut seen = HashSet::new();
    for gateway in adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .filter(|gateway| is_private_ipv4(gateway))
    {
        for port in probe_ports.iter().copied() {
            let key = format!("{gateway}:{port}");
            if !seen.insert(key.clone()) {
                continue;
            }
            let command = format!("udp_probe local={port} remote={gateway}:{port}");
            let name = format!("udp_probe_{}_{}", gateway.replace('.', "_"), port);
            let output = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
                Ok(socket) => {
                    let _ = socket.set_write_timeout(Some(Duration::from_millis(200)));
                    let payload = format!("JLIVEF-{port}");
                    match socket.send_to(payload.as_bytes(), format!("{gateway}:{port}")) {
                        Ok(sent) => format!("sent {} bytes", sent),
                        Err(error) => format!("send failed: {error}"),
                    }
                }
                Err(error) => format!("bind failed: {error}"),
            };
            raw_commands.push(CommandArtifact {
                name,
                command,
                output,
            });
        }
    }
}

pub(super) fn pktmon_is_running(status: &str) -> bool {
    let lower = status.to_lowercase();
    if lower.contains("not running") || lower.contains("не запущен") {
        return false;
    }
    lower.contains("running")
        || lower.contains("collected data")
        || lower.contains("собранные данные")
}

pub(super) fn pktmon_filters_empty(filters: &str) -> bool {
    let lower = filters.to_lowercase();
    lower.contains("none") || lower.contains("нет")
}

pub(super) fn pause_for_enter() {
    print!("Press Enter to return to menu...");
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}
