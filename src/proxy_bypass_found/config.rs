use super::*;

#[derive(Clone, Debug)]
pub(crate) struct LocalConfigArtifact {
    pub(crate) path: String,
    pub(crate) content: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ProxyConfigSignal {
    pub(crate) path: String,
    pub(crate) tun_interfaces: Vec<String>,
    pub(crate) tun_addresses: Vec<String>,
    pub(crate) auto_route: bool,
    pub(crate) strict_route: bool,
    pub(crate) final_proxy: bool,
    pub(crate) loopback_proxy_outbounds: Vec<String>,
    pub(crate) route_process_names: Vec<String>,
}

pub(super) fn collect_proxy_config_artifacts(
    raw_commands: &mut Vec<CommandArtifact>,
    process_map: &HashMap<u32, ProcessMeta>,
) -> Vec<LocalConfigArtifact> {
    let mut paths = HashSet::<PathBuf>::new();
    let path_re = Regex::new(r#"(?i)([A-Z]:\\[^"\r\n]+\.(?:json|ya?ml))"#).unwrap();

    for process in process_map.values() {
        let process_text =
            format!("{} {} {}", process.name, process.path, process.command_line).to_lowercase();
        if !is_vpn_proxy_process_text(&process_text) {
            continue;
        }
        for cap in path_re.captures_iter(&process.command_line) {
            let candidate = PathBuf::from(&cap[1]);
            if candidate.exists() {
                paths.insert(candidate);
            }
        }
    }

    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let happ_config = PathBuf::from(local_app_data)
            .join("Happ")
            .join("config.json");
        if happ_config.exists() {
            paths.insert(happ_config);
        }
    }

    let mut collected = Vec::new();
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    for (index, path) in paths.into_iter().enumerate() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > 512 * 1024 {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        raw_commands.push(CommandArtifact {
            name: format!("proxy_config_{}", index + 1),
            command: format!("read proxy config {}", path.display()),
            output: content.clone(),
        });
        collected.push(LocalConfigArtifact {
            path: path.display().to_string(),
            content,
        });
    }
    collected
}

pub(super) fn parse_proxy_config_signal(
    artifact: &LocalConfigArtifact,
) -> Option<ProxyConfigSignal> {
    let value = parse_proxy_config_value(&artifact.content)?;
    let mut signal = ProxyConfigSignal {
        path: artifact.path.clone(),
        ..ProxyConfigSignal::default()
    };

    for inbound in json_items(value.get("inbounds")) {
        if !json_string(inbound, "type").eq_ignore_ascii_case("tun") {
            continue;
        }
        let interface_name = json_string(inbound, "interface_name");
        if !interface_name.is_empty() {
            signal.tun_interfaces.push(interface_name);
        }
        signal
            .tun_addresses
            .extend(json_string_list(inbound, "address"));
        signal.auto_route |= json_enabled_flag(inbound, "auto_route");
        signal.strict_route |= json_enabled_flag(inbound, "strict_route");
    }

    for outbound in json_items(value.get("outbounds")) {
        if !json_string(outbound, "type").eq_ignore_ascii_case("socks") {
            continue;
        }
        let server = normalize_ip_literal(&json_string(outbound, "server"));
        let port = json_u16(outbound, "server_port").unwrap_or(0);
        if is_loopback_ip(&server) && port != 0 {
            signal
                .loopback_proxy_outbounds
                .push(format!("{}:{}", server, port));
        }
    }

    let route = value.get("route").unwrap_or(&Value::Null);
    signal.final_proxy = json_string(route, "final").eq_ignore_ascii_case("proxy");
    for rule in json_items(route.get("rules")) {
        signal
            .route_process_names
            .extend(json_string_list(rule, "process_name"));
    }

    signal.tun_interfaces.sort();
    signal.tun_interfaces.dedup();
    signal.tun_addresses.sort();
    signal.tun_addresses.dedup();
    signal.loopback_proxy_outbounds.sort();
    signal.loopback_proxy_outbounds.dedup();
    signal.route_process_names.sort();
    signal.route_process_names.dedup();

    if signal.tun_interfaces.is_empty()
        && signal.tun_addresses.is_empty()
        && signal.loopback_proxy_outbounds.is_empty()
        && !signal.final_proxy
    {
        None
    } else {
        Some(signal)
    }
}

fn parse_proxy_config_value(content: &str) -> Option<Value> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }

    serde_json::from_str::<Value>(trimmed)
        .ok()
        .or_else(|| serde_yaml::from_str::<Value>(trimmed).ok())
}
