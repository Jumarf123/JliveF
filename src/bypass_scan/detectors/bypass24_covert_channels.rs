use std::collections::HashSet;

use sysinfo::System;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, query_event_records, run_command, truncate_text,
};

const ACTIVE_PROCESS_NAMES: &[&str] = &[
    "tor.exe",
    "openvpn.exe",
    "wireguard.exe",
    "wg.exe",
    "tailscaled.exe",
    "tailscale.exe",
    "zerotier-one.exe",
    "cloudflared.exe",
    "chisel.exe",
    "frpc.exe",
    "frps.exe",
    "ngrok.exe",
    "sing-box.exe",
    "hysteria.exe",
    "tuic-client.exe",
];

const ADAPTER_KEYWORDS: &[&str] = &[
    "wireguard",
    "openvpn",
    "tun",
    "tap",
    "tailscale",
    "zerotier",
    "radmin vpn",
    "protonvpn",
    "warp",
    "sing-tun",
];

const TUNNEL_PORTS: &[u16] = &[1080, 1081, 9050, 9051, 1194, 1701, 1723, 51820];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        24,
        "bypass24_covert_channels",
        "Covert channel tooling (VPN/Tor/tunnels)",
        "No high-confidence covert-channel bypass pattern found.",
    );

    let adapters = find_connected_tunnel_adapters();
    let processes = find_active_tunnel_processes();
    let listener_hits = find_tunnel_listener_hits();

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        180,
    );
    let sec_events = query_event_records("Security", &[4688], 220);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 180);
    let command_hits = collect_tunnel_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    let signal_count = (if !adapters.is_empty() { 1 } else { 0 })
        + (if !processes.is_empty() { 1 } else { 0 })
        + (if !listener_hits.is_empty() { 1 } else { 0 })
        + (if !command_hits.is_empty() { 1 } else { 0 });

    if !processes.is_empty() && !listener_hits.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Active tunnel process/listener correlates with tunnel command telemetry.".to_string();
    } else if signal_count >= 2 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Multiple covert-channel indicators detected; validate authorization scope."
                .to_string();
    } else if signal_count >= 1 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Single covert-channel indicator detected (active-state policy).".to_string();
    }

    if !adapters.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "netsh interface ipv4 show interfaces".to_string(),
            summary: format!("{} connected adapter indicator(s)", adapters.len()),
            details: adapters.join("; "),
        });
    }

    if !processes.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "live process list".to_string(),
            summary: format!("{} active tunnel process(es)", processes.len()),
            details: processes.join("; "),
        });
    }

    if !listener_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "netstat -ano".to_string(),
            summary: format!("{} suspicious listener(s)", listener_hits.len()),
            details: listener_hits.join("; "),
        });
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} explicit tunnel command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate with approved VPN inventory and perimeter DNS/proxy/firewall telemetry."
                .to_string(),
        );
    }

    logger.log(
        "bypass24_covert_channels",
        "info",
        "covert channel check complete",
        serde_json::json!({
            "adapters": adapters.len(),
            "processes": processes.len(),
            "listeners": listener_hits.len(),
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn find_connected_tunnel_adapters() -> Vec<String> {
    let out =
        run_command("netsh", &["interface", "ipv4", "show", "interfaces"]).unwrap_or_default();
    if out.trim().is_empty() {
        return Vec::new();
    }

    let mut hits = Vec::new();
    for line in out.lines().skip(2) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if !(lower.contains("connected") || lower.contains("подключ")) {
            continue;
        }

        if !ADAPTER_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
            continue;
        }

        hits.push(trimmed.to_string());
    }
    hits.sort();
    hits.dedup();
    hits
}

fn find_active_tunnel_processes() -> Vec<String> {
    let mut sys = System::new_all();
    sys.refresh_processes();

    let mut hits = Vec::new();
    for proc_ in sys.processes().values() {
        let name = proc_.name().to_lowercase();
        if !ACTIVE_PROCESS_NAMES.iter().any(|needle| *needle == name) {
            continue;
        }
        hits.push(format!("{} (pid={})", proc_.name(), proc_.pid()));
    }

    hits.sort();
    hits.dedup();
    hits
}

fn find_tunnel_listener_hits() -> Vec<String> {
    let Some(out) = run_command("netstat", &["-ano"]) else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    for line in out.lines() {
        let normalized = line.trim().to_lowercase();
        if !(normalized.contains("listen") || normalized.contains("прослуш")) {
            continue;
        }
        if !looks_like_tunnel_listener_line(&normalized) {
            continue;
        }
        hits.push(truncate_text(line.trim(), 180));
    }

    hits.sort();
    hits.dedup();
    hits
}

fn collect_tunnel_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let command_line = extract_event_data_value(&event.raw_xml, "CommandLine")
                .or_else(|| extract_event_data_value(&event.raw_xml, "ProcessCommandLine"))
                .or_else(|| extract_event_data_value(&event.raw_xml, "ScriptBlockText"))
                .unwrap_or_default();
            let image = extract_event_data_value(&event.raw_xml, "Image")
                .or_else(|| extract_event_data_value(&event.raw_xml, "NewProcessName"))
                .unwrap_or_default();
            let corpus = format!("{image} {command_line}");
            if !looks_like_tunnel_command(&corpus) {
                continue;
            }

            let hit = format!(
                "{} | {} Event {} | image={} cmd={}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&image, 100),
                truncate_text(&command_line, 180),
            );

            if seen.insert(hit.clone()) {
                hits.push(hit);
            }
        }
    }
    hits.sort();
    hits
}

fn looks_like_tunnel_listener_line(text: &str) -> bool {
    TUNNEL_PORTS
        .iter()
        .any(|port| text.contains(&format!(":{port}")))
}

fn looks_like_tunnel_command(text: &str) -> bool {
    let normalized = text.to_lowercase();

    // Exclude scanner/inspection style commands to reduce self-noise.
    if normalized.contains("get-netadapter")
        || normalized.contains("get-process")
        || normalized.contains("netsh interface")
        || normalized.contains("netstat -ano")
        || normalized.contains("where-object")
        || normalized.contains("select-object")
        || normalized.contains("convertto-json")
        || normalized.contains(" -match ")
    {
        return false;
    }

    if normalized.contains("ssh ")
        && (normalized.contains(" -d ")
            || normalized.contains(" -r ")
            || normalized.contains(" -l ")
            || normalized.contains(" -w "))
    {
        return true;
    }

    let explicit_tools = [
        (
            "tor.exe",
            &[" --service", " -f ", " --socksport", " torrc "][..],
        ),
        ("openvpn", &[" --config", " --remote", " --daemon"][..]),
        (
            "wireguard.exe",
            &[" /installtunnelservice", " /uninstalltunnelservice"][..],
        ),
        ("wg-quick", &[" up ", " down "][..]),
        ("tailscale", &[" up", " funnel", " serve", " ssh "][..]),
        ("zerotier-one", &[" -d", " join ", " orbit "][..]),
        ("cloudflared", &[" tunnel ", " access tcp "][..]),
        ("chisel", &[" client ", " server "][..]),
        ("frpc", &[" -c ", " --config"][..]),
        ("frps", &[" -c ", " --config"][..]),
        ("ngrok", &[" tcp ", " http ", " tls "][..]),
        ("sing-box", &[" run", " -c "][..]),
        ("hysteria", &[" client ", " -c "][..]),
        ("tuic-client", &[" -c ", " --config"][..]),
    ];
    explicit_tools.iter().any(|(tool, verbs)| {
        normalized.contains(tool) && verbs.iter().any(|v| normalized.contains(v))
    })
}

#[cfg(test)]
mod tests {
    use super::{looks_like_tunnel_command, looks_like_tunnel_listener_line};

    #[test]
    fn tunnel_command_matcher_requires_explicit_tool_or_ssh_tunnel_shape() {
        assert!(looks_like_tunnel_command(
            "chisel client 1.2.3.4:443 R:socks"
        ));
        assert!(looks_like_tunnel_command("ssh -D 9050 user@host"));
        assert!(!looks_like_tunnel_command(
            "C:\\Windows\\system32\\SearchProtocolHost.exe"
        ));
        assert!(!looks_like_tunnel_command("AggregatorHost.exe"));
    }

    #[test]
    fn listener_line_matcher_detects_common_tunnel_ports() {
        assert!(looks_like_tunnel_listener_line(
            "tcp    0.0.0.0:9050   0.0.0.0:0   listen"
        ));
        assert!(!looks_like_tunnel_listener_line(
            "tcp    0.0.0.0:80   0.0.0.0:0   listen"
        ));
    }
}
