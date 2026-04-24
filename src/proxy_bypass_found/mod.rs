use anyhow::{Context, Result, bail};
use chrono::Local;
use rayon::prelude::*;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsString, c_void};
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sysinfo::System;
use uuid::Uuid;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

mod collection;
mod config;
mod helpers;
mod models;
mod packet_capture;
mod packet_detections;
mod parsers;
mod pktmon;
mod process_memory;

use crate::bypass_scan::utils::{run_command, run_command_uncached, run_powershell, truncate_text};
#[cfg(test)]
use collection::sanitize_nbtstat_output;
use collection::{
    collect_command, collect_commands_parallel, collect_fresh_command, pause_for_enter,
    perform_udp_proxy_probes, ping_private_gateways, ping_private_minecraft_peers,
    pktmon_filters_empty, pktmon_is_running, probe_private_gateways_nbtstat,
    probe_private_gateways_tcp, probe_private_minecraft_peers_nbtstat,
    probe_private_minecraft_peers_tcp, sanitize_command_output,
};
use config::{
    LocalConfigArtifact, ProxyConfigSignal, collect_proxy_config_artifacts,
    parse_proxy_config_signal,
};
use helpers::{is_virtualish_adapter, is_vpn_proxy_process_text};
use models::{
    AdapterBlock, ArpEntry, CommandArtifact, Confidence, Finding, HandleGuard, ModuleInfo,
    NbtstatInfo, NetstatTcp, ParallelCommandSpec, PathHop, PortProxyEntry, ProcessMeta, ScanReport,
};
use packet_capture::{
    PacketCaptureAnalysis, PacketTupleStat, analyze_pktmon_capture, find_packet_tuple_stat,
    packet_activity_for_tuple,
};
use packet_detections::{
    detect_local_proxy_chain, detect_minecraft_handshake_target_mismatch,
    detect_packet_relay_correlation, detect_private_peer_packet_proxy,
};
use parsers::{
    merge_neighbor_macs, parse_arp_entries, parse_gateway_nbtstat, parse_gateway_open_tcp_ports,
    parse_gateway_ping_ttls, parse_ipconfig_adapters, parse_netsh_neighbor_macs, parse_netstat_tcp,
    parse_pathping_hops, parse_peer_nbtstat, parse_peer_open_tcp_ports, parse_portproxy_entries,
};
use pktmon::{add_pktmon_live_flow_filters, add_pktmon_probe_filters, detect_pktmon};
#[cfg(test)]
use process_memory::{contains_ascii_case_insensitive, normalize_faker_memory_hits};
use process_memory::{detect_minecraft_process_memory, detect_process_memory};

const MODULE_NAME: &str = "proxy bypass found (beta-test)";
const DEFAULT_MINECRAFT_PORT_HINTS: &[u16] = &[25565, 25566, 25575];
const STATIC_PROXY_PROBE_PORTS: &[u16] = &[15000];
const WINDOWS_HOST_PROBE_PORTS: &[u16] = &[135, 139, 445, 3389];
const MIN_FAKER_MEMORY_STRING_HITS: usize = 3;
const MAX_TRACKED_MINECRAFT_PORTS: usize = 12;
const PROCESS_QUERY_FLAGS: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0);

const POWERSHELL_SNAPSHOT_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'

$processes = @(Get-CimInstance Win32_Process |
  Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine)

$minecraftPids = @($processes |
  Where-Object {
    $_.CommandLine -match '(?i)minecraft|\.minecraft|net\.minecraft|minecraft\.launcher|--gameDir|--assetsDir|lwjgl|fabric|forge|legacylauncher|tlauncher|knotclient|lunarclient|badlion|feather'
  } |
  Select-Object -ExpandProperty ProcessId)

$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Where-Object {
    $_.OwningProcess -in $minecraftPids -or
    $_.LocalPort -in 15000,25565,25566,25575 -or
    $_.RemotePort -in 15000,25565,25566,25575 -or
    $_.State -in 'Listen','Established','SynSent','SynReceived'
  } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)

$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
  Where-Object {
    $_.OwningProcess -in $minecraftPids -or
    $_.LocalPort -in 53,67,68,5353,5355,15000,25565,25566,25575
  } |
  Select-Object LocalAddress, LocalPort, OwningProcess)

$netAdapter = @(Get-NetAdapter -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceDescription, InterfaceIndex, Status, MacAddress, LinkSpeed, MediaType, PhysicalMediaType, NdisPhysicalMedium)

$neighborsV4 = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -notmatch '^224\.|^239\.|^255\.|^0\.' } |
  Select-Object InterfaceAlias, InterfaceIndex, IPAddress, LinkLayerAddress, State)

$neighborsV6 = @(Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -and $_.IPAddress -notlike 'ff*' -and $_.IPAddress -ne '::' } |
  Select-Object InterfaceAlias, InterfaceIndex, IPAddress, LinkLayerAddress, State)

$routesV4 = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
  Select-Object InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric)

$routesV6 = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
  Where-Object { $_.DestinationPrefix -eq '::/0' } |
  Select-Object InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric)

$ipConfig = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue |
  Select-Object InterfaceAlias, InterfaceIndex, InterfaceDescription,
    @{Name='IPv4Address';Expression={$_.IPv4Address.IPAddress}},
    @{Name='IPv4DefaultGateway';Expression={$_.IPv4DefaultGateway.NextHop}},
    @{Name='IPv6Address';Expression={$_.IPv6Address.IPAddress}},
    @{Name='IPv6DefaultGateway';Expression={$_.IPv6DefaultGateway.NextHop}},
    @{Name='DNSServer';Expression={$_.DNSServer.ServerAddresses}})

$ipInterfaces = @(Get-NetIPInterface -ErrorAction SilentlyContinue |
  Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, Forwarding, WeakHostSend, WeakHostReceive, RouterDiscovery, Dhcp, ManagedAddressConfiguration, OtherStatefulConfiguration, InterfaceMetric)

$adapterBindings = @(Get-NetAdapterBinding -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceDescription, ComponentID, DisplayName, Enabled)

$netNat = @(Get-NetNat -ErrorAction SilentlyContinue |
  Select-Object Name, InternalIPInterfaceAddressPrefix, ExternalIPInterfaceAddressPrefix)

$netNatStaticMapping = @(Get-NetNatStaticMapping -ErrorAction SilentlyContinue |
  Select-Object NatName, ExternalIPAddress, ExternalPort, InternalIPAddress, InternalPort, Protocol)

$connectionProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity)

[PSCustomObject]@{
  Processes = $processes
  Tcp = $tcp
  Udp = $udp
  NetAdapter = $netAdapter
  NeighborsV4 = $neighborsV4
  NeighborsV6 = $neighborsV6
  RoutesV4 = $routesV4
  RoutesV6 = $routesV6
  NetIPConfiguration = $ipConfig
  IPInterfaces = $ipInterfaces
  AdapterBindings = $adapterBindings
  NetNat = $netNat
  NetNatStaticMapping = $netNatStaticMapping
  ConnectionProfiles = $connectionProfiles
} | ConvertTo-Json -Depth 5 -Compress
"#;

pub fn run_proxy_bypass_found() -> Result<()> {
    println!("\n{MODULE_NAME}");
    println!(
        "Collecting ipconfig /all, arp -a -v, pktmon, pathping, netstat, route and process-memory evidence..."
    );

    let report = run_scan()?;
    print_console_summary(&report);

    let (txt_path, json_path, log_path) = save_report(&report)?;
    println!("\nReport saved:");
    println!("  {}", txt_path.display());
    println!("  {}", json_path.display());
    println!("  {}", log_path.display());

    pause_for_enter();
    Ok(())
}

fn run_scan() -> Result<ScanReport> {
    let started = Local::now();
    let timer = Instant::now();
    let mut findings = Vec::new();
    let mut raw_commands = Vec::new();

    let pathping_handle = std::thread::spawn(|| {
        let args = ["/n", "/h", "6", "/q", "1", "/w", "250", "1.1.1.1"];
        let command = format!("pathping {}", args.join(" "));
        let output = sanitize_command_output(
            "pathping_1_1_1_1",
            "pathping",
            run_command_uncached("pathping", &args)
                .unwrap_or_else(|| format!("Failed to run {command}")),
        );
        CommandArtifact {
            name: "pathping_1_1_1_1".to_string(),
            command,
            output,
        }
    });

    let baseline_outputs = collect_commands_parallel(
        &mut raw_commands,
        &[
            ParallelCommandSpec {
                name: "ipconfig_all",
                exe: "ipconfig",
                args: &["/all"],
            },
            ParallelCommandSpec {
                name: "netstat_tcp",
                exe: "netstat",
                args: &["-ano", "-p", "tcp"],
            },
            ParallelCommandSpec {
                name: "netstat_all",
                exe: "netstat",
                args: &["-ano"],
            },
        ],
    );
    let ipconfig_all = baseline_outputs
        .get("ipconfig_all")
        .cloned()
        .unwrap_or_default();
    let adapters = parse_ipconfig_adapters(&ipconfig_all);
    ping_private_gateways(&mut raw_commands, &adapters);
    probe_private_gateways_nbtstat(&mut raw_commands, &adapters);
    let arp_all = collect_command(&mut raw_commands, "arp_all_verbose", "arp", &["-a", "-v"]);
    let pathping_artifact = pathping_handle.join().unwrap_or_else(|_| CommandArtifact {
        name: "pathping_1_1_1_1".to_string(),
        command: "pathping /n /h 6 /q 1 /w 250 1.1.1.1".to_string(),
        output: "Failed to join pathping worker".to_string(),
    });
    let pathping = pathping_artifact.output.clone();
    raw_commands.push(pathping_artifact);
    let netstat = baseline_outputs
        .get("netstat_tcp")
        .cloned()
        .unwrap_or_default();
    let snapshot_raw = run_powershell(POWERSHELL_SNAPSHOT_SCRIPT).unwrap_or_default();
    raw_commands.push(CommandArtifact {
        name: "powershell_snapshot".to_string(),
        command: "PowerShell process/connection/network snapshot".to_string(),
        output: snapshot_raw.clone(),
    });

    let netstat_entries = parse_netstat_tcp(&netstat);
    let snapshot_json = serde_json::from_str::<Value>(snapshot_raw.trim()).unwrap_or(Value::Null);
    let process_map = process_map_from_snapshot(&snapshot_json);
    let proxy_config_artifacts = collect_proxy_config_artifacts(&mut raw_commands, &process_map);
    let proxy_config_signals: Vec<ProxyConfigSignal> = proxy_config_artifacts
        .iter()
        .filter_map(parse_proxy_config_signal)
        .collect();
    if !proxy_config_signals.is_empty() {
        let mut lines = proxy_config_signals
            .iter()
            .map(|signal| {
                format!(
                    "{} | tun_if={:?} tun_addr={:?} auto_route={} strict_route={} final_proxy={} loopback_outbounds={:?} route_processes={:?}",
                    signal.path,
                    signal.tun_interfaces,
                    signal.tun_addresses,
                    signal.auto_route,
                    signal.strict_route,
                    signal.final_proxy,
                    signal.loopback_proxy_outbounds,
                    signal.route_process_names
                )
            })
            .collect::<Vec<_>>();
        lines.sort();
        lines.dedup();
        raw_commands.push(CommandArtifact {
            name: "proxy_config_signal_summary".to_string(),
            command: "parse proxy JSON/YAML configs".to_string(),
            output: lines.join("\n"),
        });
    }
    let minecraft_ports = discover_minecraft_ports(&netstat_entries, &snapshot_json, &process_map);
    let probe_ports = build_proxy_probe_ports(&minecraft_ports);
    raw_commands.push(CommandArtifact {
        name: "minecraft_port_profile".to_string(),
        command: "auto-detected minecraft/proxy ports".to_string(),
        output: format!(
            "minecraft_ports={:?}\nproxy_probe_ports={:?}",
            minecraft_ports, probe_ports
        ),
    });
    let active_minecraft =
        active_minecraft_connections(&netstat_entries, &process_map, &minecraft_ports);

    probe_private_gateways_tcp(&mut raw_commands, &adapters, &probe_ports);
    let pktmon_capture_root = std::env::temp_dir().join(format!(
        "jlivef_proxy_bypass_{}",
        Uuid::new_v4().as_simple()
    ));
    let _ = fs::create_dir_all(&pktmon_capture_root);
    let pktmon_capture_etl = pktmon_capture_root.join("capture.etl");
    let pktmon_capture_pcap = pktmon_capture_root.join("capture.pcapng");
    let pktmon_status_before = collect_fresh_command(
        &mut raw_commands,
        "pktmon_status_before",
        "pktmon",
        &["status"],
    );
    let pktmon_filters_before = collect_fresh_command(
        &mut raw_commands,
        "pktmon_filter_list_before",
        "pktmon",
        &["filter", "list"],
    );
    let pktmon_initially_running = pktmon_is_running(&pktmon_status_before);
    let pktmon_temp_filters_added =
        !pktmon_initially_running && pktmon_filters_empty(&pktmon_filters_before);
    if pktmon_temp_filters_added {
        add_pktmon_probe_filters(&mut raw_commands, &adapters, &probe_ports);
        add_pktmon_live_flow_filters(
            &mut raw_commands,
            &process_map,
            &netstat_entries,
            &minecraft_ports,
        );
    }

    if !pktmon_initially_running {
        collect_fresh_command(
            &mut raw_commands,
            "pktmon_start_probe",
            "pktmon",
            &[
                "start",
                "--capture",
                "--comp",
                "nics",
                "--pkt-size",
                "0",
                "--file-name",
                &pktmon_capture_etl.display().to_string(),
            ],
        );
    }
    let pktmon_status_after_start = collect_fresh_command(
        &mut raw_commands,
        "pktmon_status_after_start",
        "pktmon",
        &["status"],
    );
    let pktmon_started_by_us =
        !pktmon_initially_running && pktmon_is_running(&pktmon_status_after_start);
    if pktmon_started_by_us {
        perform_udp_proxy_probes(&mut raw_commands, &adapters, &probe_ports);
        std::thread::sleep(Duration::from_millis(1500));
    }

    let route_netsh_outputs = collect_commands_parallel(
        &mut raw_commands,
        &[
            ParallelCommandSpec {
                name: "route_print_ipv4",
                exe: "route",
                args: &["print", "-4"],
            },
            ParallelCommandSpec {
                name: "route_print_ipv6",
                exe: "route",
                args: &["print", "-6"],
            },
            ParallelCommandSpec {
                name: "netsh_ipv4_config",
                exe: "netsh",
                args: &["interface", "ipv4", "show", "config"],
            },
            ParallelCommandSpec {
                name: "netsh_ipv4_neighbors",
                exe: "netsh",
                args: &["interface", "ipv4", "show", "neighbors"],
            },
            ParallelCommandSpec {
                name: "netsh_ipv6_neighbors",
                exe: "netsh",
                args: &["interface", "ipv6", "show", "neighbors"],
            },
            ParallelCommandSpec {
                name: "netsh_portproxy_show_all",
                exe: "netsh",
                args: &["interface", "portproxy", "show", "all"],
            },
            ParallelCommandSpec {
                name: "netsh_bridge_show_adapter",
                exe: "netsh",
                args: &["bridge", "show", "adapter"],
            },
            ParallelCommandSpec {
                name: "netsh_bridge_list",
                exe: "netsh",
                args: &["bridge", "list"],
            },
            ParallelCommandSpec {
                name: "netsh_wlan_show_interfaces",
                exe: "netsh",
                args: &["wlan", "show", "interfaces"],
            },
            ParallelCommandSpec {
                name: "netsh_wlan_show_hostednetwork",
                exe: "netsh",
                args: &["wlan", "show", "hostednetwork"],
            },
        ],
    );
    let route_print = route_netsh_outputs
        .get("route_print_ipv4")
        .cloned()
        .unwrap_or_default();
    let route_print_ipv6 = route_netsh_outputs
        .get("route_print_ipv6")
        .cloned()
        .unwrap_or_default();
    let netsh_ipv4_config = route_netsh_outputs
        .get("netsh_ipv4_config")
        .cloned()
        .unwrap_or_default();
    let netsh_ipv4_neighbors = route_netsh_outputs
        .get("netsh_ipv4_neighbors")
        .cloned()
        .unwrap_or_default();
    let netsh_ipv6_neighbors = route_netsh_outputs
        .get("netsh_ipv6_neighbors")
        .cloned()
        .unwrap_or_default();
    let netsh_portproxy = route_netsh_outputs
        .get("netsh_portproxy_show_all")
        .cloned()
        .unwrap_or_default();
    let netsh_bridge_show_adapter = route_netsh_outputs
        .get("netsh_bridge_show_adapter")
        .cloned()
        .unwrap_or_default();
    let netsh_bridge_list = route_netsh_outputs
        .get("netsh_bridge_list")
        .cloned()
        .unwrap_or_default();
    let netsh_wlan_show_interfaces = route_netsh_outputs
        .get("netsh_wlan_show_interfaces")
        .cloned()
        .unwrap_or_default();
    let netsh_wlan_show_hostednetwork = route_netsh_outputs
        .get("netsh_wlan_show_hostednetwork")
        .cloned()
        .unwrap_or_default();
    let pktmon_filters_probe = collect_fresh_command(
        &mut raw_commands,
        "pktmon_filter_list_probe",
        "pktmon",
        &["filter", "list"],
    );
    let pktmon_counters_probe = collect_fresh_command(
        &mut raw_commands,
        "pktmon_counters_probe",
        "pktmon",
        &["counters"],
    );
    let pktmon_counters_json = collect_fresh_command(
        &mut raw_commands,
        "pktmon_counters_probe_json",
        "pktmon",
        &["counters", "--json"],
    );
    if pktmon_started_by_us {
        collect_fresh_command(&mut raw_commands, "pktmon_stop_probe", "pktmon", &["stop"]);
    }
    if pktmon_temp_filters_added {
        collect_fresh_command(
            &mut raw_commands,
            "pktmon_filter_remove_probe",
            "pktmon",
            &["filter", "remove"],
        );
    }
    let _pktmon_status_after = collect_fresh_command(
        &mut raw_commands,
        "pktmon_status_after_probe",
        "pktmon",
        &["status"],
    );
    let packet_capture_analysis = analyze_pktmon_capture(
        &mut raw_commands,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        &pktmon_capture_etl,
        &pktmon_capture_pcap,
        pktmon_started_by_us,
    );

    if !active_minecraft.is_empty() {
        ping_private_minecraft_peers(&mut raw_commands, &active_minecraft);
        probe_private_minecraft_peers_tcp(&mut raw_commands, &active_minecraft, &probe_ports);
        probe_private_minecraft_peers_nbtstat(&mut raw_commands, &active_minecraft);
    }
    let arp_peer_refresh = if active_minecraft.is_empty() {
        String::new()
    } else {
        collect_fresh_command(
            &mut raw_commands,
            "arp_all_verbose_peer_refresh",
            "arp",
            &["-a", "-v"],
        )
    };
    let netsh_ipv4_neighbors_refresh = if active_minecraft.is_empty() {
        String::new()
    } else {
        collect_fresh_command(
            &mut raw_commands,
            "netsh_ipv4_neighbors_peer_refresh",
            "netsh",
            &["interface", "ipv4", "show", "neighbors"],
        )
    };

    let arp_entries = parse_arp_entries(&format!("{arp_all}\n{arp_peer_refresh}"));
    let pathping_hops = parse_pathping_hops(&pathping);
    let gateway_ping_ttls = parse_gateway_ping_ttls(&raw_commands);
    let gateway_tcp_ports = parse_gateway_open_tcp_ports(&raw_commands);
    let gateway_nbtstat = parse_gateway_nbtstat(&raw_commands);
    let peer_tcp_ports = parse_peer_open_tcp_ports(&raw_commands);
    let peer_nbtstat = parse_peer_nbtstat(&raw_commands);
    let mut neighbor_macs = neighbor_macs_from_snapshot(&snapshot_json);
    neighbor_macs = merge_neighbor_macs(
        &neighbor_macs,
        &parse_netsh_neighbor_macs(&format!(
            "{netsh_ipv4_neighbors}\n{netsh_ipv4_neighbors_refresh}\n{netsh_ipv6_neighbors}"
        )),
    );
    let has_minecraft_flow_context = !active_minecraft.is_empty();

    detect_pktmon(
        &mut findings,
        &pktmon_status_after_start,
        &pktmon_filters_probe,
        &pktmon_counters_probe,
        &pktmon_counters_json,
        has_minecraft_flow_context,
        &probe_ports,
    );
    detect_powershell_snapshot(
        &mut findings,
        &snapshot_json,
        &process_map,
        &adapters,
        &netstat_entries,
        &active_minecraft,
        &minecraft_ports,
        &probe_ports,
    );
    detect_minecraft_process_network_context(
        &mut findings,
        &adapters,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        &gateway_ping_ttls,
    );
    detect_local_proxy_chain(
        &mut findings,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        packet_capture_analysis.as_ref(),
    );
    detect_packet_relay_correlation(
        &mut findings,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        packet_capture_analysis.as_ref(),
    );
    detect_minecraft_handshake_target_mismatch(
        &mut findings,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        packet_capture_analysis.as_ref(),
    );
    detect_private_peer_packet_proxy(
        &mut findings,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
        packet_capture_analysis.as_ref(),
    );
    detect_network_topology(
        &mut findings,
        &adapters,
        &arp_entries,
        &pathping_hops,
        &gateway_ping_ttls,
        &gateway_tcp_ports,
        &gateway_nbtstat,
        &netstat_entries,
        &process_map,
        &neighbor_macs,
        &route_print,
        &route_print_ipv6,
        &netsh_ipv4_config,
        &netsh_ipv4_neighbors,
        &netsh_ipv6_neighbors,
        &netsh_portproxy,
        &minecraft_ports,
        &probe_ports,
    );
    detect_vpn_proxy_context(&mut findings, &adapters, &snapshot_json);
    detect_portproxy(
        &mut findings,
        &netsh_portproxy,
        &minecraft_ports,
        &probe_ports,
    );
    detect_nat_static_mappings(
        &mut findings,
        &snapshot_json,
        &process_map,
        &minecraft_ports,
        &probe_ports,
    );
    detect_network_bridge(
        &mut findings,
        &snapshot_json,
        &active_minecraft,
        &process_map,
        &netsh_bridge_show_adapter,
        &netsh_bridge_list,
        &netsh_wlan_show_interfaces,
        &netsh_wlan_show_hostednetwork,
    );
    detect_private_peer_host_evidence(
        &mut findings,
        &active_minecraft,
        &process_map,
        &peer_tcp_ports,
        &peer_nbtstat,
        &arp_entries,
        &neighbor_macs,
        &adapters,
        &probe_ports,
    );
    detect_process_memory(&mut findings);
    detect_minecraft_process_memory(
        &mut findings,
        &process_map,
        &netstat_entries,
        &minecraft_ports,
    );

    findings.sort_by(|a, b| {
        b.confidence
            .score()
            .cmp(&a.confidence.score())
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.title.cmp(&b.title))
    });

    let overall = if findings.iter().any(|f| f.confidence == Confidence::High) {
        "detected_high_confidence".to_string()
    } else if findings.iter().any(|f| f.confidence == Confidence::Medium) {
        "suspicious_manual_review".to_string()
    } else if findings.iter().any(|f| f.confidence == Confidence::Low) {
        "weak_context_only".to_string()
    } else {
        "clean".to_string()
    };

    Ok(ScanReport {
        module: MODULE_NAME.to_string(),
        started_at: started.format("%Y-%m-%d %H:%M:%S").to_string(),
        finished_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        duration_ms: timer.elapsed().as_millis(),
        overall,
        findings,
        adapters,
        arp_entries,
        pathping_hops,
        raw_commands,
        source_notes: vec![
            "Normal home-router shape is not a detection by itself. Network findings require Minecraft/proxy-port activity together with Windows ICS, direct PC-to-PC routing, host-like gateway traits, MAC anomalies, or route/path anomalies.".to_string(),
            "VPN/proxy adapters are reported as context because they intentionally proxy traffic, but generic packet interception drivers are ignored.".to_string(),
            "When pktmon is not already running, this module starts a short packet capture with temporary Minecraft/proxy filters for both probe traffic and live flow endpoints, then removes those filters after collection.".to_string(),
            "Minecraft-related ports are auto-discovered from live java/javaw Minecraft traffic and UDP endpoints, so custom ports like 25715 are tracked automatically.".to_string(),
            "future_hook/xameleon evidence is accepted only from explorer.exe loaded modules or explorer.exe memory strings.".to_string(),
            "IPv6, adapter bindings, forwarding state, neighbors and NAT state are collected for correlation, but protocol bindings are not modified by the scanner.".to_string(),
            "Bridge state, NAT static mappings and private-peer host evidence are correlated only when they align with Minecraft/proxy-port activity.".to_string(),
            "Pktmon captures are converted to pcapng and checked for Minecraft handshake target mismatch, so a private relay endpoint can be compared against the host/port declared inside the packet stream.".to_string(),
            "Minecraft process-specific detections are based on the java/javaw process itself: its exact flow tuple, bound adapter, loopback peer shape and faker-specific strings in process memory.".to_string(),
        ],
    })
}

fn detect_powershell_snapshot(
    findings: &mut Vec<Finding>,
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    adapters: &[AdapterBlock],
    netstat_entries: &[NetstatTcp],
    active_minecraft: &[NetstatTcp],
    minecraft_ports: &[u16],
    probe_ports: &[u16],
) {
    detect_tcp_udp_connections(
        findings,
        snapshot,
        process_map,
        adapters,
        netstat_entries,
        minecraft_ports,
        probe_ports,
    );
    detect_local_forwarding_state(findings, snapshot, active_minecraft, adapters);
}

fn detect_tcp_udp_connections(
    findings: &mut Vec<Finding>,
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    adapters: &[AdapterBlock],
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    probe_ports: &[u16],
) {
    let gateways = collect_default_gateways(snapshot, adapters);
    let mut strong = Vec::new();
    let mut medium = Vec::new();
    let mut relevant_pids = HashSet::new();

    for connection in netstat_entries {
        let local_port = Some(connection.local_port);
        let remote_port = Some(connection.remote_port);
        let local_addr = connection.local_addr.clone();
        let remote_addr = connection.remote_addr.clone();
        let state = connection.state.clone();
        let pid = connection.pid;
        let process = process_map.get(&pid);
        let proc_name = process.map(|p| p.name.as_str()).unwrap_or("unknown");
        let proc_cmd = process.map(|p| p.command_line.as_str()).unwrap_or("");
        let client_process = is_minecraft_client_process(proc_name, proc_cmd);

        let local_match = local_port
            .map(|port| minecraft_ports.contains(&port))
            .unwrap_or(false);
        let remote_match = remote_port
            .map(|port| minecraft_ports.contains(&port))
            .unwrap_or(false);
        if !local_match && !remote_match {
            continue;
        }
        if remote_port.unwrap_or(0) == 0 || is_wildcard_ip(&remote_addr) {
            continue;
        }

        let line = format!(
            "{state} {}:{} -> {}:{} PID {} {} | {}",
            local_addr,
            local_port.unwrap_or(0),
            remote_addr,
            remote_port.unwrap_or(0),
            pid,
            proc_name,
            truncate_text(proc_cmd, 260)
        );

        if remote_match
            && is_lan_ip(&remote_addr)
            && gateways.contains(&remote_addr)
            && client_process
        {
            strong.push(format!(
                "Minecraft client connects to default gateway on Minecraft/proxy port: {line}"
            ));
            relevant_pids.insert(pid);
        } else if remote_match && is_lan_ip(&remote_addr) && client_process {
            medium.push(format!(
                "Minecraft client connects to private LAN peer on Minecraft/proxy port: {line}"
            ));
            relevant_pids.insert(pid);
        } else if local_match
            && client_process
            && !is_wildcard_ip(&local_addr)
            && !is_loopback_ip(&local_addr)
            && is_lan_ip(&remote_addr)
        {
            medium.push(format!(
                "Minecraft client/process uses a local Minecraft port while talking to a LAN peer: {line}"
            ));
            relevant_pids.insert(pid);
        }
    }

    let udp_context =
        collect_udp_minecraft_context(snapshot, process_map, &relevant_pids, probe_ports);
    if !udp_context.is_empty() {
        if !strong.is_empty() {
            strong.extend(udp_context);
        } else if !medium.is_empty() {
            medium.extend(udp_context);
        }
    }

    if !strong.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "connections".to_string(),
            title: "Active PC-proxy-compatible Minecraft connection found".to_string(),
            details: strong,
        });
    }
    if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "connections".to_string(),
            title: "LAN Minecraft/proxy port activity needs review".to_string(),
            details: medium,
        });
    }
}

fn detect_local_forwarding_state(
    findings: &mut Vec<Finding>,
    snapshot: &Value,
    active_minecraft: &[NetstatTcp],
    adapters: &[AdapterBlock],
) {
    if active_minecraft.is_empty() {
        return;
    }

    let forwarded = json_items(snapshot.get("IPInterfaces"))
        .into_iter()
        .filter(|item| json_enabled_flag(item, "Forwarding"))
        .map(|item| {
            (
                json_string(item, "InterfaceAlias"),
                json_string(item, "AddressFamily"),
            )
        })
        .filter(|(alias, _)| !alias.is_empty())
        .collect::<Vec<_>>();
    if forwarded.is_empty() {
        return;
    }

    let nat_count = json_items(snapshot.get("NetNat")).len();
    let mut medium = Vec::new();

    for config in json_items(snapshot.get("NetIPConfiguration")) {
        let alias = json_string(config, "InterfaceAlias");
        if alias.is_empty() {
            continue;
        }
        if !forwarded
            .iter()
            .any(|(forwarded_alias, _)| forwarded_alias == &alias)
        {
            continue;
        }
        let desc = json_string(config, "InterfaceDescription");
        let adapter = adapters.iter().find(|adapter| {
            adapter.description.eq_ignore_ascii_case(&desc)
                || adapter.name.eq_ignore_ascii_case(&alias)
                || adapter.name.to_lowercase().contains(&alias.to_lowercase())
        });
        if adapter.is_some_and(is_virtualish_adapter) {
            continue;
        }

        let mut local_addrs = json_string_list(config, "IPv4Address");
        local_addrs.extend(json_string_list(config, "IPv6Address"));
        if !active_minecraft
            .iter()
            .any(|connection| local_addrs.contains(&connection.local_addr))
        {
            continue;
        }

        let bindings = summarize_important_bindings(snapshot, &alias);
        medium.push(format!(
            "{} | desc={} forwarding_enabled=true nat_entries={} local_addresses={:?} bindings={}",
            alias,
            desc,
            nat_count,
            local_addrs,
            bindings.unwrap_or_else(|| "unknown".to_string())
        ));
    }

    if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "forwarding_state".to_string(),
            title: "Local interface forwarding is enabled during Minecraft LAN traffic".to_string(),
            details: medium,
        });
    }
}

fn detect_network_topology(
    findings: &mut Vec<Finding>,
    adapters: &[AdapterBlock],
    arp_entries: &[ArpEntry],
    pathping_hops: &[PathHop],
    gateway_ping_ttls: &HashMap<String, u16>,
    gateway_tcp_ports: &HashMap<String, Vec<u16>>,
    gateway_nbtstat: &HashMap<String, NbtstatInfo>,
    netstat_entries: &[NetstatTcp],
    process_map: &HashMap<u32, ProcessMeta>,
    neighbor_macs: &HashMap<String, HashSet<String>>,
    route_print: &str,
    route_print_ipv6: &str,
    netsh_ipv4_config: &str,
    netsh_ipv4_neighbors: &str,
    netsh_ipv6_neighbors: &str,
    _netsh_portproxy: &str,
    minecraft_ports: &[u16],
    probe_ports: &[u16],
) {
    let first_hop = pathping_hops.first().map(|h| h.ip.as_str());
    let active_minecraft =
        active_minecraft_connections(netstat_entries, process_map, minecraft_ports);
    let mut high = Vec::new();
    let mut medium = Vec::new();

    for adapter in adapters {
        if adapter.ipv4_addresses.is_empty() {
            continue;
        }
        if is_virtualish_adapter(adapter) {
            continue;
        }
        let Some(gateway) = adapter
            .default_gateways
            .iter()
            .find(|gw| is_private_ipv4(gw))
        else {
            continue;
        };
        let gateway_arp = arp_entries.iter().find(|e| e.ip == *gateway);
        let gateway_mac = gateway_arp
            .map(|e| e.mac.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let gateway_is_dhcp = adapter.dhcp_servers.iter().any(|dhcp| dhcp == gateway);
        let gateway_is_dns = adapter.dns_servers.iter().any(|dns| dns == gateway);
        let path_first_is_gateway = first_hop.map(|hop| hop == gateway).unwrap_or(false);
        let path_first_differs = first_hop
            .map(|hop| is_valid_ipv4(hop) && hop != gateway)
            .unwrap_or(false);
        let gateway_laa = is_locally_administered_mac(&gateway_mac);
        let gateway_kind = gateway_arp
            .map(|e| e.kind.clone())
            .unwrap_or_else(|| "missing-arp".to_string());
        let gateway_ping_ttl = gateway_ping_ttls.get(gateway).copied();
        let has_minecraft_to_gateway = active_minecraft
            .iter()
            .any(|conn| conn.remote_addr == *gateway);
        let has_any_minecraft = !active_minecraft.is_empty();
        let gateway_open_ports = gateway_tcp_ports.get(gateway).cloned().unwrap_or_default();
        let gateway_open_proxy_ports = gateway_open_ports
            .iter()
            .copied()
            .filter(|port| probe_ports.contains(port))
            .collect::<Vec<_>>();
        let gateway_open_host_ports = gateway_open_ports
            .iter()
            .copied()
            .filter(|port| WINDOWS_HOST_PROBE_PORTS.contains(port))
            .collect::<Vec<_>>();
        let gateway_nbt = gateway_nbtstat.get(gateway).cloned().unwrap_or_default();
        let gateway_nbt_names = gateway_nbt.names.clone();
        let gateway_nbt_host = gateway_nbt.workstation_service || gateway_nbt.file_server_service;
        let gateway_has_mc_port = gateway_open_proxy_ports
            .iter()
            .any(|port| minecraft_ports.contains(port));
        let arp_peer_count = count_private_dynamic_peers_for_adapter(adapter, arp_entries);
        let gateway_mac_private_ip_count = count_private_ips_with_mac(&gateway_mac, arp_entries);
        let route_mentions_gateway = route_print.contains(gateway)
            || route_print_ipv6.contains(gateway)
            || netsh_ipv4_config.contains(gateway);
        let neighbor_mentions_gateway =
            netsh_ipv4_neighbors.contains(gateway) || netsh_ipv6_neighbors.contains(gateway);
        let active_minecraft_flows =
            summarize_active_minecraft_flows(&active_minecraft, process_map, gateway);
        let peer_same_mac_as_gateway = minecraft_peer_matches_gateway_mac(
            adapter,
            &active_minecraft,
            &gateway_mac,
            gateway,
            arp_entries,
            neighbor_macs,
        );
        let signal_score = network_signal_score(
            has_minecraft_to_gateway,
            &peer_same_mac_as_gateway,
            gateway_ping_ttl,
            gateway_is_dhcp,
            gateway_is_dns,
            gateway_laa,
            &gateway_open_proxy_ports,
            &gateway_open_host_ports,
            gateway_nbt_host,
            path_first_differs,
            gateway_mac_private_ip_count,
        );
        let gateway_windowsish = gateway_ping_ttl.is_some_and(|ttl| ttl >= 120)
            && (!gateway_open_host_ports.is_empty() || gateway_nbt_host);
        let gateway_config_host = gateway_is_dhcp || gateway_is_dns;
        let hard_anchor_count = usize::from(has_minecraft_to_gateway)
            + usize::from(!peer_same_mac_as_gateway.is_empty())
            + usize::from(!gateway_open_proxy_ports.is_empty())
            + usize::from(gateway_nbt_host)
            + usize::from(gateway_windowsish)
            + usize::from(gateway_mac_private_ip_count >= 2)
            + usize::from(path_first_differs);

        let detail = format!(
            "{} | ipv4={:?} gateway={} dhcp_server_match={} dns_match={} pathping_first_hop_match={} path_first_differs={} gateway_mac={} gateway_arp_type={} laa_mac={} gateway_ping_ttl={:?} arp_private_dynamic_peers={} gateway_mac_private_ip_count={} minecraft_to_gateway={} any_minecraft_detected={} tracked_minecraft_ports={:?} active_minecraft_flows={:?} peer_same_mac_as_gateway={:?} gateway_open_proxy_ports={:?} gateway_open_host_ports={:?} gateway_nbt_host={} gateway_nbt_names={:?} signal_score={} route_mentions_gateway={} neighbor_mentions_gateway={}",
            adapter.name,
            adapter.ipv4_addresses,
            gateway,
            gateway_is_dhcp,
            gateway_is_dns,
            path_first_is_gateway,
            path_first_differs,
            gateway_mac,
            gateway_kind,
            gateway_laa,
            gateway_ping_ttl,
            arp_peer_count,
            gateway_mac_private_ip_count,
            has_minecraft_to_gateway,
            has_any_minecraft,
            minecraft_ports,
            active_minecraft_flows,
            peer_same_mac_as_gateway,
            gateway_open_proxy_ports,
            gateway_open_host_ports,
            gateway_nbt_host,
            gateway_nbt_names,
            signal_score,
            route_mentions_gateway,
            neighbor_mentions_gateway
        );

        let is_ics_gateway = gateway == "192.168.137.1"
            || adapter
                .dhcp_servers
                .iter()
                .any(|dhcp| dhcp == "192.168.137.1");

        if !peer_same_mac_as_gateway.is_empty() {
            high.push(format!(
                "Active Minecraft private peer resolves to the same MAC as the local gateway, consistent with proxy-ARP / PC-gateway behavior: {detail}"
            ));
        } else if has_minecraft_to_gateway
            && gateway_windowsish
            && gateway_config_host
            && (!gateway_open_proxy_ports.is_empty()
                || gateway_mac_private_ip_count >= 2
                || is_ics_gateway)
        {
            high.push(format!(
                "Minecraft client traffic terminates on a host-like private gateway that also supplies local network settings: {detail}"
            ));
        } else if has_any_minecraft
            && gateway_nbt_host
            && !gateway_open_host_ports.is_empty()
            && (!gateway_open_proxy_ports.is_empty()
                || gateway_ping_ttl.is_some_and(|ttl| ttl >= 120))
        {
            high.push(format!(
                "Private gateway behaves like a Windows host in NetBIOS/SMB while also exposing bypass-compatible traffic traits during Minecraft activity: {detail}"
            ));
        } else if has_any_minecraft
            && signal_score >= 12
            && hard_anchor_count >= 3
            && (gateway_windowsish || gateway_config_host)
        {
            high.push(format!(
                "Multiple hard network indicators correlate on the private gateway during Minecraft activity: {detail}"
            ));
        } else if is_ics_gateway && has_any_minecraft {
            medium.push(format!(
                "Windows ICS/Mobile Hotspot style gateway is active during Minecraft traffic: {detail}"
            ));
        } else if has_any_minecraft && gateway_nbt_host && !gateway_open_host_ports.is_empty() {
            medium.push(format!(
                "Private gateway responds like a Windows host over NetBIOS/SMB during Minecraft activity: {detail}"
            ));
        } else if has_any_minecraft
            && gateway_windowsish
            && gateway_config_host
            && (gateway_laa || gateway_mac_private_ip_count >= 2 || path_first_differs)
        {
            medium.push(format!(
                "A host-like private gateway is carrying Minecraft traffic with supporting topology anomalies: {detail}"
            ));
        } else if has_any_minecraft && gateway_laa && gateway_is_dhcp && gateway_is_dns {
            medium.push(format!(
                "Active Minecraft traffic with LAA gateway acting as DHCP and DNS: {detail}"
            ));
        } else if has_any_minecraft
            && gateway_has_mc_port
            && (gateway_windowsish || gateway_laa || gateway_mac_private_ip_count >= 2)
        {
            medium.push(format!(
                "Active Minecraft traffic with a private gateway exposing Minecraft/proxy ports and host-like traits: {detail}"
            ));
        } else if has_any_minecraft
            && gateway_mac_private_ip_count >= 2
            && (gateway_laa || has_minecraft_to_gateway || gateway_nbt_host)
        {
            medium.push(format!(
                "Active Minecraft traffic with gateway MAC reused by multiple private ARP entries: {detail}"
            ));
        } else if has_any_minecraft && path_first_differs && (gateway_laa || gateway_windowsish) {
            medium.push(format!(
                "Active Minecraft traffic with first-hop mismatch and host-like private gateway traits: {detail}"
            ));
        } else if has_any_minecraft && arp_peer_count <= 2 && gateway_laa && gateway_arp.is_some() {
            medium.push(format!(
                "Active Minecraft traffic on sparse PC-to-PC style LAN with LAA gateway: {detail}"
            ));
        } else if has_any_minecraft
            && signal_score >= 9
            && hard_anchor_count >= 2
            && (gateway_windowsish || gateway_nbt_host || !gateway_open_proxy_ports.is_empty())
        {
            medium.push(format!(
                "Multiple independent network indicators correlate on the private gateway during Minecraft activity: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "network_topology".to_string(),
            title: "Second-PC network evidence matches PC-to-PC proxy bypass".to_string(),
            details: high,
        });
    }
    if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "network_topology".to_string(),
            title: "Second-PC network topology is suspicious for proxy bypass".to_string(),
            details: medium,
        });
    }
}

fn active_minecraft_connections(
    entries: &[NetstatTcp],
    process_map: &HashMap<u32, ProcessMeta>,
    minecraft_ports: &[u16],
) -> Vec<NetstatTcp> {
    entries
        .iter()
        .filter(|conn| {
            let port_match = minecraft_ports.contains(&conn.remote_port)
                || minecraft_ports.contains(&conn.local_port);
            let active_state = matches!(
                conn.state.to_ascii_uppercase().as_str(),
                "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
            );
            let client_process = process_map
                .get(&conn.pid)
                .map(|p| is_minecraft_client_process(&p.name, &p.command_line))
                .unwrap_or(false);
            port_match
                && active_state
                && client_process
                && conn.remote_port != 0
                && !is_wildcard_ip(&conn.remote_addr)
                && is_lan_ip(&conn.remote_addr)
        })
        .cloned()
        .collect()
}

fn active_minecraft_upstream_connections(
    entries: &[NetstatTcp],
    process_map: &HashMap<u32, ProcessMeta>,
    minecraft_ports: &[u16],
) -> Vec<NetstatTcp> {
    entries
        .iter()
        .filter(|conn| {
            let port_match = minecraft_ports.contains(&conn.remote_port)
                || minecraft_ports.contains(&conn.local_port);
            let active_state = matches!(
                conn.state.to_ascii_uppercase().as_str(),
                "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
            );
            let client_process = process_map
                .get(&conn.pid)
                .map(|p| is_minecraft_client_process(&p.name, &p.command_line))
                .unwrap_or(false);
            port_match
                && active_state
                && client_process
                && conn.remote_port != 0
                && !is_wildcard_ip(&conn.remote_addr)
                && !is_loopback_ip(&conn.remote_addr)
        })
        .cloned()
        .collect()
}

fn active_snapshot_minecraft_connections(
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    minecraft_ports: &[u16],
) -> Vec<NetstatTcp> {
    let mut entries = Vec::new();
    for item in json_items(snapshot.get("Tcp")) {
        let Some(local_port) = json_u16(item, "LocalPort") else {
            continue;
        };
        let Some(remote_port) = json_u16(item, "RemotePort") else {
            continue;
        };
        let local_addr = normalize_ip_literal(&json_string(item, "LocalAddress"));
        let remote_addr = normalize_ip_literal(&json_string(item, "RemoteAddress"));
        let state = json_string(item, "State");
        let pid = json_u32(item, "OwningProcess").unwrap_or(0);
        let Some(process) = process_map.get(&pid) else {
            continue;
        };
        if !is_minecraft_client_process(&process.name, &process.command_line) {
            continue;
        }
        if !matches!(
            state.to_ascii_uppercase().as_str(),
            "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
        ) {
            continue;
        }
        if !(minecraft_ports.contains(&remote_port) || minecraft_ports.contains(&local_port)) {
            continue;
        }
        if remote_port == 0 || is_wildcard_ip(&remote_addr) || !is_lan_ip(&remote_addr) {
            continue;
        }
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

fn collect_local_proxy_relay_pids(
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
) -> HashSet<u32> {
    let upstream_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if upstream_flows.is_empty() {
        return HashSet::new();
    }

    let remote_endpoints = upstream_flows
        .iter()
        .map(|flow| (flow.remote_addr.clone(), flow.remote_port))
        .collect::<HashSet<_>>();
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

    let mut relay_pids = HashSet::new();
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
        let Some(process) = process_map.get(&entry.pid) else {
            continue;
        };
        if is_minecraft_client_process(&process.name, &process.command_line) {
            continue;
        }
        let has_listener = loopback_listener_ports
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
                && loopback_listener_ports
                    .get(&entry.pid)
                    .is_some_and(|ports| {
                        ports.contains(&loopback.local_port)
                            || ports.contains(&loopback.remote_port)
                    })
        });
        if has_listener || has_loopback_session {
            relay_pids.insert(entry.pid);
        }
    }

    relay_pids
}

fn summarize_active_minecraft_flows(
    entries: &[NetstatTcp],
    process_map: &HashMap<u32, ProcessMeta>,
    gateway: &str,
) -> Vec<String> {
    entries
        .iter()
        .filter(|conn| conn.remote_addr == gateway || is_lan_ip(&conn.remote_addr))
        .take(6)
        .map(|conn| {
            let process = process_map
                .get(&conn.pid)
                .map(|p| p.name.as_str())
                .unwrap_or("unknown");
            format!(
                "{}:{} -> {}:{} {} PID {} {}",
                conn.local_addr,
                conn.local_port,
                conn.remote_addr,
                conn.remote_port,
                conn.state,
                conn.pid,
                process
            )
        })
        .collect()
}

fn count_private_dynamic_peers_for_adapter(
    adapter: &AdapterBlock,
    arp_entries: &[ArpEntry],
) -> usize {
    arp_entries
        .iter()
        .filter(|entry| {
            is_private_ipv4(&entry.ip)
                && entry.kind.eq_ignore_ascii_case("dynamic")
                && adapter
                    .ipv4_addresses
                    .iter()
                    .any(|addr| entry.interface.contains(addr))
        })
        .count()
}

fn count_private_ips_with_mac(mac: &str, arp_entries: &[ArpEntry]) -> usize {
    if mac.is_empty() || mac.eq_ignore_ascii_case("unknown") {
        return 0;
    }
    arp_entries
        .iter()
        .filter(|entry| {
            entry.mac.eq_ignore_ascii_case(mac)
                && entry.kind.eq_ignore_ascii_case("dynamic")
                && is_private_ipv4(&entry.ip)
        })
        .map(|entry| entry.ip.as_str())
        .collect::<HashSet<_>>()
        .len()
}

fn network_signal_score(
    has_minecraft_to_gateway: bool,
    peer_same_mac_as_gateway: &[String],
    gateway_ping_ttl: Option<u16>,
    gateway_is_dhcp: bool,
    gateway_is_dns: bool,
    gateway_laa: bool,
    gateway_open_proxy_ports: &[u16],
    gateway_open_host_ports: &[u16],
    gateway_nbt_host: bool,
    path_first_differs: bool,
    gateway_mac_private_ip_count: usize,
) -> u8 {
    let mut score = 0u8;
    if has_minecraft_to_gateway {
        score = score.saturating_add(4);
    }
    if !peer_same_mac_as_gateway.is_empty() {
        score = score.saturating_add(5);
    }
    if gateway_ping_ttl.is_some_and(|ttl| ttl >= 120) {
        score = score.saturating_add(3);
    }
    if gateway_is_dhcp {
        score = score.saturating_add(2);
    }
    if gateway_is_dns {
        score = score.saturating_add(2);
    }
    if gateway_laa {
        score = score.saturating_add(2);
    }
    if !gateway_open_proxy_ports.is_empty() {
        score = score.saturating_add(2);
    }
    if !gateway_open_host_ports.is_empty() {
        score = score.saturating_add(2);
    }
    if gateway_nbt_host {
        score = score.saturating_add(3);
    }
    if path_first_differs {
        score = score.saturating_add(2);
    }
    if gateway_mac_private_ip_count >= 2 {
        score = score.saturating_add(2);
    }
    score
}

fn minecraft_peer_matches_gateway_mac(
    adapter: &AdapterBlock,
    active_minecraft: &[NetstatTcp],
    gateway_mac: &str,
    gateway_ip: &str,
    arp_entries: &[ArpEntry],
    neighbor_macs: &HashMap<String, HashSet<String>>,
) -> Vec<String> {
    if gateway_mac.is_empty() || gateway_mac.eq_ignore_ascii_case("unknown") {
        return Vec::new();
    }

    let mut hits = Vec::new();
    let subnet_mask = adapter
        .subnet_masks
        .first()
        .map(String::as_str)
        .unwrap_or("");

    for connection in active_minecraft
        .iter()
        .filter(|connection| adapter.ipv4_addresses.contains(&connection.local_addr))
    {
        let remote = connection.remote_addr.as_str();
        if !is_private_ipv4(remote)
            || remote == gateway_ip
            || !ipv4_in_same_subnet(&connection.local_addr, remote, subnet_mask)
        {
            continue;
        }

        let macs = macs_for_ip(remote, arp_entries, neighbor_macs);
        if macs.iter().any(|mac| mac.eq_ignore_ascii_case(gateway_mac)) {
            hits.push(format!(
                "{}:{} -> {}:{} shares gateway MAC {}",
                connection.local_addr,
                connection.local_port,
                connection.remote_addr,
                connection.remote_port,
                gateway_mac
            ));
        }
    }

    hits.sort();
    hits.dedup();
    hits
}

fn macs_for_ip(
    ip: &str,
    arp_entries: &[ArpEntry],
    neighbor_macs: &HashMap<String, HashSet<String>>,
) -> HashSet<String> {
    let mut macs = arp_entries
        .iter()
        .filter(|entry| entry.ip == ip && !entry.mac.trim().is_empty())
        .map(|entry| normalize_mac_display(&entry.mac))
        .collect::<HashSet<_>>();

    if let Some(extra) = neighbor_macs.get(ip) {
        macs.extend(extra.iter().cloned());
    }

    macs.retain(|mac| {
        !mac.trim().is_empty()
            && !mac.eq_ignore_ascii_case("unknown")
            && mac != "00-00-00-00-00-00"
            && mac != "FF-FF-FF-FF-FF-FF"
    });
    macs
}

fn ipv4_in_same_subnet(left: &str, right: &str, mask: &str) -> bool {
    let Some(left_octets) = parse_ipv4_octets(left) else {
        return false;
    };
    let Some(right_octets) = parse_ipv4_octets(right) else {
        return false;
    };
    let Some(mask_octets) = parse_ipv4_octets(mask) else {
        return false;
    };

    left_octets
        .iter()
        .zip(right_octets.iter())
        .zip(mask_octets.iter())
        .all(|((left_part, right_part), mask_part)| {
            (left_part & mask_part) == (right_part & mask_part)
        })
}

fn detect_vpn_proxy_context(
    findings: &mut Vec<Finding>,
    adapters: &[AdapterBlock],
    snapshot: &Value,
) {
    let adapter_needles = [
        "vpn",
        "tap",
        "tun",
        "wintun",
        "wireguard",
        "openvpn",
        "zerotier",
        "tailscale",
        "proton",
        "nord",
        "mullvad",
        "expressvpn",
        "hamachi",
        "radmin",
        "outline",
        "clash",
        "v2ray",
        "nekoray",
        "sing-box",
    ];

    let mut adapter_hits = Vec::new();
    for adapter in adapters {
        let text = format!(
            "{} {} {}",
            adapter.name, adapter.description, adapter.physical_address
        )
        .to_lowercase();
        if adapter_needles.iter().any(|needle| text.contains(needle))
            && (!adapter.ipv4_addresses.is_empty() || !adapter.default_gateways.is_empty())
        {
            adapter_hits.push(format!(
                "{} | desc={} | ipv4={:?} | gw={:?} | dns={:?}",
                adapter.name,
                adapter.description,
                adapter.ipv4_addresses,
                adapter.default_gateways,
                adapter.dns_servers
            ));
        }
    }

    let mut process_hits = Vec::new();
    for process in json_items(snapshot.get("Processes")) {
        let meta = process_meta_from_value(process);
        let text = format!("{} {} {}", meta.name, meta.path, meta.command_line).to_lowercase();
        if is_self_collection_text(&text) {
            continue;
        }
        if is_vpn_proxy_process_text(&text) {
            process_hits.push(format!(
                "PID {} {} | {}",
                meta.pid,
                meta.name,
                truncate_text(&meta.command_line, 260)
            ));
        }
    }
    process_hits.truncate(12);

    let mut details = Vec::new();
    details.extend(adapter_hits);
    details.extend(process_hits);
    if !details.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "vpn_proxy_context".to_string(),
            title: "VPN/proxy context detected".to_string(),
            details,
        });
    }
}

#[allow(dead_code)]
fn detect_same_pc_proxy_chain(
    findings: &mut Vec<Finding>,
    adapters: &[AdapterBlock],
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    proxy_config_artifacts: &[LocalConfigArtifact],
) {
    let upstream_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if upstream_flows.is_empty() {
        return;
    }

    let tunnel_adapters = adapters
        .iter()
        .filter(|adapter| {
            is_virtualish_adapter(adapter)
                && (!adapter.ipv4_addresses.is_empty() || !adapter.default_gateways.is_empty())
        })
        .collect::<Vec<_>>();
    if tunnel_adapters.is_empty() {
        return;
    }

    let mut tunnel_flow_details = Vec::new();
    let mut tunnel_flow_pids = HashSet::new();
    let mut tunnel_flow_remote_endpoints = HashSet::new();
    for flow in &upstream_flows {
        let Some(adapter) = tunnel_adapters.iter().find(|adapter| {
            adapter
                .ipv4_addresses
                .iter()
                .any(|ip| ip.eq_ignore_ascii_case(&flow.local_addr))
        }) else {
            continue;
        };
        let process = process_map.get(&flow.pid);
        let proc_name = process.map(|p| p.name.as_str()).unwrap_or("unknown");
        let proc_cmd = process.map(|p| p.command_line.as_str()).unwrap_or("");
        tunnel_flow_details.push(format!(
            "{} | {}:{} -> {}:{} {} PID {} {} | {}",
            adapter.name,
            flow.local_addr,
            flow.local_port,
            flow.remote_addr,
            flow.remote_port,
            flow.state,
            flow.pid,
            proc_name,
            truncate_text(proc_cmd, 220)
        ));
        tunnel_flow_pids.insert(flow.pid);
        tunnel_flow_remote_endpoints.insert(format!("{}:{}", flow.remote_addr, flow.remote_port));
    }
    if tunnel_flow_details.is_empty() {
        return;
    }

    let mut proxy_listener_details = Vec::new();
    let mut proxy_listener_ports = HashSet::new();
    for entry in netstat_entries {
        if !matches!(
            entry.state.to_ascii_uppercase().as_str(),
            "LISTEN" | "LISTENING"
        ) {
            continue;
        }
        if !is_loopback_ip(&entry.local_addr) {
            continue;
        }
        let Some(process) = process_map.get(&entry.pid) else {
            continue;
        };
        let process_text =
            format!("{} {} {}", process.name, process.path, process.command_line).to_lowercase();
        if !is_vpn_proxy_process_text(&process_text) {
            continue;
        }
        proxy_listener_details.push(format!(
            "{}:{} LISTEN PID {} {} | {}",
            entry.local_addr,
            entry.local_port,
            entry.pid,
            process.name,
            truncate_text(&process.command_line, 220)
        ));
        proxy_listener_ports.insert(entry.local_port);
    }

    let mut proxy_udp_details = Vec::new();
    for item in json_items(snapshot.get("Udp")) {
        let Some(local_port) = json_u16(item, "LocalPort") else {
            continue;
        };
        let local_addr = normalize_ip_literal(&json_string(item, "LocalAddress"));
        if !is_loopback_ip(&local_addr) {
            continue;
        }
        let pid = json_u32(item, "OwningProcess").unwrap_or(0);
        let Some(process) = process_map.get(&pid) else {
            continue;
        };
        let process_text =
            format!("{} {} {}", process.name, process.path, process.command_line).to_lowercase();
        if !is_vpn_proxy_process_text(&process_text) {
            continue;
        }
        proxy_udp_details.push(format!(
            "UDP {}:{} PID {} {} | {}",
            local_addr,
            local_port,
            pid,
            process.name,
            truncate_text(&process.command_line, 220)
        ));
        proxy_listener_ports.insert(local_port);
    }

    let relay_listener_pids = netstat_entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.state.to_ascii_uppercase().as_str(),
                "LISTEN" | "LISTENING"
            )
        })
        .filter(|entry| {
            is_loopback_ip(&entry.local_addr) && minecraft_ports.contains(&entry.local_port)
        })
        .filter_map(|entry| {
            process_map.get(&entry.pid).and_then(|process| {
                if is_minecraft_client_process(&process.name, &process.command_line) {
                    Some(entry.pid)
                } else {
                    None
                }
            })
        })
        .collect::<HashSet<_>>();

    let mut relay_details = Vec::new();
    for entry in netstat_entries {
        if !relay_listener_pids.contains(&entry.pid) {
            continue;
        }
        let is_listener = matches!(
            entry.state.to_ascii_uppercase().as_str(),
            "LISTEN" | "LISTENING"
        ) && is_loopback_ip(&entry.local_addr)
            && minecraft_ports.contains(&entry.local_port);
        let is_loopback_peer = matches!(
            entry.state.to_ascii_uppercase().as_str(),
            "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
        ) && is_loopback_ip(&entry.local_addr)
            && is_loopback_ip(&entry.remote_addr)
            && minecraft_ports.contains(&entry.local_port);
        if !(is_listener || is_loopback_peer) {
            continue;
        }
        let process = process_map.get(&entry.pid);
        let proc_name = process.map(|p| p.name.as_str()).unwrap_or("unknown");
        relay_details.push(format!(
            "{}:{} -> {}:{} {} PID {} {}",
            entry.local_addr,
            entry.local_port,
            entry.remote_addr,
            entry.remote_port,
            entry.state,
            entry.pid,
            proc_name
        ));
    }

    let mut shared_remote_details = Vec::new();
    let mut grouped_flows = HashMap::<(String, u16), HashSet<u32>>::new();
    for flow in &upstream_flows {
        grouped_flows
            .entry((flow.remote_addr.clone(), flow.remote_port))
            .or_default()
            .insert(flow.pid);
    }
    for ((remote_addr, remote_port), pids) in grouped_flows {
        if pids.len() < 2 {
            continue;
        }
        let mut pid_list = pids.into_iter().collect::<Vec<_>>();
        pid_list.sort_unstable();
        let relay_present = pid_list.iter().any(|pid| relay_listener_pids.contains(pid));
        if relay_present {
            shared_remote_details.push(format!(
                "Multiple Minecraft java processes share the same upstream endpoint {}:{} | pids={:?}",
                remote_addr, remote_port, pid_list
            ));
        }
    }

    let config_signals = proxy_config_artifacts
        .iter()
        .filter_map(parse_proxy_config_signal)
        .collect::<Vec<_>>();
    let mut config_details = Vec::new();
    for signal in &config_signals {
        let matches_tunnel = signal.tun_interfaces.iter().any(|interface_name| {
            tunnel_adapters.iter().any(|adapter| {
                adapter.name.eq_ignore_ascii_case(interface_name)
                    || adapter
                        .description
                        .to_lowercase()
                        .contains(&interface_name.to_lowercase())
            })
        }) || signal.tun_addresses.iter().any(|tun_address| {
            tunnel_adapters.iter().any(|adapter| {
                adapter
                    .ipv4_addresses
                    .iter()
                    .any(|ip| tun_address.starts_with(&format!("{ip}/")) || tun_address == ip)
            })
        });
        if !matches_tunnel {
            continue;
        }
        if !signal.final_proxy || signal.loopback_proxy_outbounds.is_empty() {
            continue;
        }
        let matched_listener_ports = signal
            .loopback_proxy_outbounds
            .iter()
            .filter_map(|value| value.rsplit_once(':'))
            .filter_map(|(_, port)| port.parse::<u16>().ok())
            .filter(|port| proxy_listener_ports.contains(port))
            .collect::<Vec<_>>();
        config_details.push(format!(
            "{} | tun_if={:?} tun_addr={:?} auto_route={} strict_route={} final=proxy socks={:?} matched_listener_ports={:?} route_processes={:?}",
            signal.path,
            signal.tun_interfaces,
            signal.tun_addresses,
            signal.auto_route,
            signal.strict_route,
            signal.loopback_proxy_outbounds,
            matched_listener_ports,
            signal.route_process_names
        ));
    }

    let anchor_count =
        usize::from(!proxy_listener_details.is_empty() || !proxy_udp_details.is_empty())
            + usize::from(!config_details.is_empty())
            + usize::from(!relay_details.is_empty() && !shared_remote_details.is_empty());

    let mut details = Vec::new();
    details.extend(tunnel_flow_details);
    details.extend(config_details);
    details.extend(proxy_listener_details);
    details.extend(proxy_udp_details);
    details.extend(relay_details);
    details.extend(shared_remote_details);
    details.sort();
    details.dedup();

    if anchor_count >= 2 {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "same_pc_proxy_chain".to_string(),
            title: "Same-PC tunnel/proxy chain is carrying Minecraft traffic".to_string(),
            details,
        });
    } else if anchor_count == 1 {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "same_pc_proxy_chain".to_string(),
            title: "Same-PC tunnel/proxy chain around Minecraft needs review".to_string(),
            details,
        });
    }
}

fn detect_minecraft_process_network_context(
    findings: &mut Vec<Finding>,
    adapters: &[AdapterBlock],
    process_map: &HashMap<u32, ProcessMeta>,
    netstat_entries: &[NetstatTcp],
    minecraft_ports: &[u16],
    gateway_ping_ttls: &HashMap<String, u16>,
) {
    let upstream_flows =
        active_minecraft_upstream_connections(netstat_entries, process_map, minecraft_ports);
    if upstream_flows.is_empty() {
        return;
    }

    let primary_physical_ipv4 = adapters
        .iter()
        .filter(|adapter| !is_virtualish_adapter(adapter))
        .flat_map(|adapter| adapter.ipv4_addresses.iter())
        .find(|ip| is_private_ipv4(ip))
        .cloned();

    let mut medium = Vec::new();
    let mut high = Vec::new();

    for flow in upstream_flows {
        let Some(process) = process_map.get(&flow.pid) else {
            continue;
        };
        let Some(adapter) = adapters.iter().find(|adapter| {
            adapter
                .ipv4_addresses
                .iter()
                .any(|ip| ip.eq_ignore_ascii_case(&flow.local_addr))
        }) else {
            continue;
        };

        let point_to_point = adapter
            .subnet_masks
            .iter()
            .any(|mask| mask == "255.255.255.252" || mask == "255.255.255.254");
        let gateway_windowsish = adapter
            .default_gateways
            .iter()
            .find_map(|gateway| gateway_ping_ttls.get(gateway))
            .is_some_and(|ttl| *ttl >= 120);
        let path = truncate_text(&process.command_line, 220);
        let detail = format!(
            "PID {} {} | {}:{} -> {}:{} via adapter {} ({}) local_ipv4={:?} gw={:?} mask={:?} primary_physical_ipv4={:?} cmd={}",
            flow.pid,
            process.name,
            flow.local_addr,
            flow.local_port,
            flow.remote_addr,
            flow.remote_port,
            adapter.name,
            adapter.description,
            adapter.ipv4_addresses,
            adapter.default_gateways,
            adapter.subnet_masks,
            primary_physical_ipv4,
            path
        );

        let fake_loopback = netstat_entries.iter().any(|entry| {
            entry.pid == flow.pid
                && matches!(
                    entry.state.to_ascii_uppercase().as_str(),
                    "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
                )
                && (is_loopback_ip(&entry.local_addr) || is_loopback_ip(&entry.remote_addr))
                && (entry.local_addr.starts_with("127.") || entry.remote_addr.starts_with("127."))
                && (minecraft_ports.contains(&entry.local_port)
                    || minecraft_ports.contains(&entry.remote_port))
        });

        if fake_loopback {
            high.push(format!(
                "Minecraft process shows loopback/fake-local peer traffic that matches faker redirect patterns: {detail}"
            ));
            continue;
        }

        if is_virtualish_adapter(adapter)
            && point_to_point
            && gateway_windowsish
            && primary_physical_ipv4
                .as_ref()
                .is_some_and(|ip| ip != &flow.local_addr)
        {
            medium.push(format!(
                "Minecraft process is sourced from a point-to-point virtual/tunnel adapter instead of the primary physical interface: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "minecraft_process_network".to_string(),
            title: "Minecraft process has faker-style loopback redirect traffic".to_string(),
            details: high,
        });
    }
    if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "minecraft_process_network".to_string(),
            title: "Minecraft process traffic is bound to a point-to-point virtual adapter"
                .to_string(),
            details: medium,
        });
    }
}

fn detect_portproxy(
    findings: &mut Vec<Finding>,
    netsh_portproxy: &str,
    minecraft_ports: &[u16],
    probe_ports: &[u16],
) {
    let entries = parse_portproxy_entries(netsh_portproxy);
    if entries.is_empty() {
        return;
    }

    let mut high = Vec::new();
    let mut medium = Vec::new();
    for entry in entries {
        let detail = format!(
            "listen {}:{} -> connect {}:{}",
            entry.listen_addr, entry.listen_port, entry.connect_addr, entry.connect_port
        );
        if probe_ports.contains(&entry.listen_port) || probe_ports.contains(&entry.connect_port) {
            high.push(format!(
                "Windows portproxy entry targets a Minecraft/proxy-related port: {detail}"
            ));
        } else if is_lan_ip(&entry.connect_addr) && minecraft_ports.contains(&entry.connect_port) {
            medium.push(format!(
                "Windows portproxy entry forwards traffic to a LAN Minecraft endpoint: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "portproxy".to_string(),
            title: "Windows portproxy rules expose Minecraft/proxy forwarding".to_string(),
            details: high,
        });
    } else if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "portproxy".to_string(),
            title: "Windows portproxy rules need review".to_string(),
            details: medium,
        });
    }
}

fn detect_nat_static_mappings(
    findings: &mut Vec<Finding>,
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    minecraft_ports: &[u16],
    probe_ports: &[u16],
) {
    let mappings = json_items(snapshot.get("NetNatStaticMapping"));
    if mappings.is_empty() {
        return;
    }

    let has_flow_context =
        !active_snapshot_minecraft_connections(snapshot, process_map, minecraft_ports).is_empty();
    let mut high = Vec::new();
    let mut medium = Vec::new();

    for mapping in mappings {
        let nat_name = json_string(mapping, "NatName");
        let external_ip = normalize_ip_literal(&json_string(mapping, "ExternalIPAddress"));
        let internal_ip = normalize_ip_literal(&json_string(mapping, "InternalIPAddress"));
        let external_port = json_u16(mapping, "ExternalPort").unwrap_or(0);
        let internal_port = json_u16(mapping, "InternalPort").unwrap_or(0);
        let protocol = json_string(mapping, "Protocol");

        let touches_proxy_port =
            probe_ports.contains(&external_port) || probe_ports.contains(&internal_port);
        let touches_mc_port =
            minecraft_ports.contains(&external_port) || minecraft_ports.contains(&internal_port);
        if !touches_proxy_port && !touches_mc_port {
            continue;
        }

        let external_any = external_ip.is_empty()
            || external_ip == "0.0.0.0"
            || external_ip == "::"
            || is_wildcard_ip(&external_ip);
        let internal_local = is_lan_ip(&internal_ip) || is_loopback_ip(&internal_ip);
        let cross_port = external_port != 0 && internal_port != 0 && external_port != internal_port;
        let proxy_only_port = external_port == 15000 || internal_port == 15000;
        let detail = format!(
            "nat={} protocol={} external={}:{} -> internal={}:{}",
            nat_name, protocol, external_ip, external_port, internal_ip, internal_port
        );

        if has_flow_context && touches_proxy_port && internal_local && (external_any || cross_port)
        {
            high.push(format!(
                "Windows NAT static mapping exposes a Minecraft/proxy path during active LAN Minecraft traffic: {detail}"
            ));
        } else if has_flow_context && proxy_only_port && internal_local {
            high.push(format!(
                "Windows NAT static mapping uses the dedicated proxy port 15000 during active LAN Minecraft traffic: {detail}"
            ));
        } else if has_flow_context && touches_mc_port && internal_local {
            medium.push(format!(
                "Windows NAT static mapping targets a LAN Minecraft port during active LAN Minecraft traffic: {detail}"
            ));
        } else if touches_proxy_port && internal_local && (external_any || cross_port) {
            medium.push(format!(
                "Windows NAT static mapping exposes a proxy-related port: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "nat_static_mapping".to_string(),
            title: "Windows NAT static mappings expose proxy/Minecraft forwarding".to_string(),
            details: high,
        });
    } else if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "nat_static_mapping".to_string(),
            title: "Windows NAT static mappings need review".to_string(),
            details: medium,
        });
    }
}

fn detect_network_bridge(
    findings: &mut Vec<Finding>,
    snapshot: &Value,
    active_minecraft: &[NetstatTcp],
    _process_map: &HashMap<u32, ProcessMeta>,
    netsh_bridge_show_adapter: &str,
    netsh_bridge_list: &str,
    netsh_wlan_show_interfaces: &str,
    netsh_wlan_show_hostednetwork: &str,
) {
    if active_minecraft.is_empty() {
        return;
    }

    let bridge_present = bridge_exists(netsh_bridge_show_adapter, netsh_bridge_list);
    let hosted_running = hostednetwork_is_running(netsh_wlan_show_hostednetwork);
    let wifi_connected = wlan_interface_is_connected(netsh_wlan_show_interfaces);
    let nat_present = !json_items(snapshot.get("NetNat")).is_empty()
        || !json_items(snapshot.get("NetNatStaticMapping")).is_empty();
    let forwarding_present = json_items(snapshot.get("IPInterfaces"))
        .into_iter()
        .any(|item| json_enabled_flag(item, "Forwarding"));
    let weak_host_present = json_items(snapshot.get("IPInterfaces"))
        .into_iter()
        .any(|item| {
            json_enabled_flag(item, "WeakHostSend") || json_enabled_flag(item, "WeakHostReceive")
        });
    let physical_adapter_summary = summarize_physical_transport(snapshot);
    let private_or_local_profile = json_items(snapshot.get("ConnectionProfiles"))
        .into_iter()
        .any(|profile| {
            let category = json_string(profile, "NetworkCategory").to_ascii_lowercase();
            let v4 = json_string(profile, "IPv4Connectivity").to_ascii_lowercase();
            let v6 = json_string(profile, "IPv6Connectivity").to_ascii_lowercase();
            category == "private"
                || matches!(v4.as_str(), "localnetwork" | "subnet")
                || matches!(v6.as_str(), "localnetwork" | "subnet")
        });

    let detail = format!(
        "bridge_present={} hosted_running={} wifi_connected={} nat_present={} forwarding_present={} weak_host_present={} private_or_local_profile={} physical_transports={}",
        bridge_present,
        hosted_running,
        wifi_connected,
        nat_present,
        forwarding_present,
        weak_host_present,
        private_or_local_profile,
        physical_adapter_summary
    );

    if bridge_present
        && hosted_running
        && wifi_connected
        && (nat_present || forwarding_present)
        && private_or_local_profile
    {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "bridge_softap".to_string(),
            title: "Bridge/SoftAP state aligns with second-PC LAN proxying".to_string(),
            details: vec![format!(
                "Windows bridge and hosted-network state are both active during LAN Minecraft traffic: {detail}"
            )],
        });
    } else if bridge_present
        && wifi_connected
        && (nat_present || forwarding_present || weak_host_present)
    {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "bridge_softap".to_string(),
            title: "Bridge state needs review during LAN Minecraft traffic".to_string(),
            details: vec![format!(
                "Windows network bridge is present with forwarding/NAT-related state during LAN Minecraft traffic: {detail}"
            )],
        });
    } else if hosted_running && wifi_connected && (nat_present || forwarding_present) {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "bridge_softap".to_string(),
            title: "Hosted-network/SoftAP state needs review during LAN Minecraft traffic".to_string(),
            details: vec![format!(
                "Windows hosted-network state is active with NAT/forwarding support during LAN Minecraft traffic: {detail}"
            )],
        });
    }
}

fn detect_private_peer_host_evidence(
    findings: &mut Vec<Finding>,
    active_minecraft: &[NetstatTcp],
    process_map: &HashMap<u32, ProcessMeta>,
    peer_tcp_ports: &HashMap<String, Vec<u16>>,
    peer_nbtstat: &HashMap<String, NbtstatInfo>,
    arp_entries: &[ArpEntry],
    neighbor_macs: &HashMap<String, HashSet<String>>,
    adapters: &[AdapterBlock],
    probe_ports: &[u16],
) {
    if active_minecraft.is_empty() {
        return;
    }

    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut seen_peers = HashSet::new();

    for connection in active_minecraft
        .iter()
        .filter(|conn| is_private_ipv4(&conn.remote_addr))
    {
        let peer = connection.remote_addr.as_str();
        if !seen_peers.insert(peer.to_string()) {
            continue;
        }

        let Some(adapter) = adapters
            .iter()
            .find(|adapter| adapter.ipv4_addresses.contains(&connection.local_addr))
        else {
            continue;
        };
        let Some(gateway) = adapter
            .default_gateways
            .iter()
            .find(|gateway| is_private_ipv4(gateway))
        else {
            continue;
        };
        if peer == gateway {
            continue;
        }

        let gateway_macs = macs_for_ip(gateway, arp_entries, neighbor_macs);
        let peer_macs = macs_for_ip(peer, arp_entries, neighbor_macs);
        let shared_gateway_mac = !gateway_macs.is_empty()
            && !peer_macs.is_empty()
            && gateway_macs.iter().any(|mac| peer_macs.contains(mac));
        let peer_mac_reuse = peer_macs
            .iter()
            .any(|mac| count_private_ips_with_mac(mac, arp_entries) >= 2);
        let open_ports = peer_tcp_ports.get(peer).cloned().unwrap_or_default();
        let open_proxy_ports = open_ports
            .iter()
            .copied()
            .filter(|port| probe_ports.contains(port))
            .collect::<Vec<_>>();
        let open_host_ports = open_ports
            .iter()
            .copied()
            .filter(|port| WINDOWS_HOST_PROBE_PORTS.contains(port))
            .collect::<Vec<_>>();
        let nbt = peer_nbtstat.get(peer).cloned().unwrap_or_default();
        let host_like_peer =
            nbt.workstation_service || nbt.file_server_service || !open_host_ports.is_empty();
        let proxy_like_peer =
            open_proxy_ports.iter().any(|port| *port == 15000) || open_proxy_ports.len() >= 2;
        let process_name = process_map
            .get(&connection.pid)
            .map(|meta| meta.name.as_str())
            .unwrap_or("unknown");
        let detail = format!(
            "{}:{} -> {}:{} {} PID {} {} | gateway={} peer_macs={:?} gateway_macs={:?} peer_mac_reuse={} open_proxy_ports={:?} open_host_ports={:?} nbt_host={} nbt_names={:?}",
            connection.local_addr,
            connection.local_port,
            connection.remote_addr,
            connection.remote_port,
            connection.state,
            connection.pid,
            process_name,
            gateway,
            peer_macs,
            gateway_macs,
            peer_mac_reuse,
            open_proxy_ports,
            open_host_ports,
            host_like_peer,
            nbt.names
        );

        if shared_gateway_mac && (host_like_peer || proxy_like_peer) {
            high.push(format!(
                "Active Minecraft LAN peer resolves like the same host as the gateway and also exposes host/proxy traits: {detail}"
            ));
        } else if proxy_like_peer && host_like_peer {
            high.push(format!(
                "Active Minecraft LAN peer exposes both Windows host services and dedicated proxy-like ports: {detail}"
            ));
        } else if shared_gateway_mac && !open_host_ports.is_empty() {
            medium.push(format!(
                "Active Minecraft LAN peer shares gateway MAC and answers on Windows host ports: {detail}"
            ));
        } else if peer_mac_reuse && proxy_like_peer && host_like_peer {
            medium.push(format!(
                "Active Minecraft LAN peer reuses a private MAC across multiple IPs and exposes host/proxy traits: {detail}"
            ));
        }
    }

    if !high.is_empty() {
        findings.push(Finding {
            confidence: Confidence::High,
            category: "private_peer".to_string(),
            title: "Private Minecraft peer behaves like the proxy host".to_string(),
            details: high,
        });
    } else if !medium.is_empty() {
        findings.push(Finding {
            confidence: Confidence::Medium,
            category: "private_peer".to_string(),
            title: "Private Minecraft peer shows host evidence that needs review".to_string(),
            details: medium,
        });
    }
}

fn bridge_exists(netsh_bridge_show_adapter: &str, netsh_bridge_list: &str) -> bool {
    let bridge_list_lower = netsh_bridge_list.to_lowercase();
    if bridge_list_lower.contains("command was not found")
        || bridge_list_lower.contains("не найден")
        || bridge_list_lower.contains("not recognized")
    {
        return false;
    }

    let guid_re = Regex::new(
        r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
    )
    .unwrap();
    if guid_re.is_match(netsh_bridge_list) {
        return true;
    }

    netsh_bridge_show_adapter
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| {
            let lower = line.to_lowercase();
            !lower.contains("id")
                && !lower.contains("name")
                && !lower.contains("adapter")
                && !line.chars().all(|ch| ch == '-' || ch == '=')
        })
}

fn hostednetwork_is_running(text: &str) -> bool {
    let lower = text.to_lowercase();
    (lower.contains("status") || lower.contains("состояние"))
        && (lower.contains("started")
            || lower.contains("running")
            || lower.contains("запущ")
            || lower.contains("выполняется"))
}

fn wlan_interface_is_connected(text: &str) -> bool {
    let lower = text.to_lowercase();
    let has_name = lower.contains("name") || lower.contains("имя");
    let connected = lower.contains("state")
        && (lower.contains("connected") || lower.contains("подключ"))
        || lower.contains("состояние") && lower.contains("подключ");
    has_name && connected
}

fn summarize_physical_transport(snapshot: &Value) -> String {
    let mut wifi = 0usize;
    let mut wired = 0usize;
    let mut other = 0usize;

    for item in json_items(snapshot.get("NetAdapter")) {
        let status = json_string(item, "Status").to_ascii_lowercase();
        if status != "up" {
            continue;
        }
        let text = format!(
            "{} {} {} {} {}",
            json_string(item, "Name"),
            json_string(item, "InterfaceDescription"),
            json_string(item, "MediaType"),
            json_string(item, "PhysicalMediaType"),
            json_string(item, "NdisPhysicalMedium"),
        )
        .to_lowercase();
        if text.contains("wireless")
            || text.contains("wi-fi")
            || text.contains("wifi")
            || text.contains("802.11")
            || text.contains("wlan")
            || text.contains("беспровод")
        {
            wifi += 1;
        } else if text.contains("ethernet")
            || text.contains("802.3")
            || text.contains("gigabit")
            || text.contains("gbe")
            || text.contains("pcie gbe")
        {
            wired += 1;
        } else {
            other += 1;
        }
    }

    format!("wifi_up={} wired_up={} other_up={}", wifi, wired, other)
}

fn discover_minecraft_ports(
    entries: &[NetstatTcp],
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
) -> Vec<u16> {
    let mut scores = HashMap::<u16, u16>::new();
    for port in DEFAULT_MINECRAFT_PORT_HINTS {
        scores.insert(*port, 10);
    }

    for connection in entries {
        let Some(process) = process_map.get(&connection.pid) else {
            continue;
        };
        if !is_minecraft_client_process(&process.name, &process.command_line) {
            continue;
        }

        let state = connection.state.to_ascii_uppercase();
        if matches!(
            state.as_str(),
            "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "SYN_RECV"
        ) {
            if is_probable_minecraft_service_port(connection.remote_port)
                && !is_wildcard_ip(&connection.remote_addr)
                && !is_loopback_ip(&connection.remote_addr)
            {
                let score = if is_lan_ip(&connection.remote_addr) {
                    8
                } else {
                    4
                };
                *scores.entry(connection.remote_port).or_default() += score;
            }
        }

        if matches!(state.as_str(), "LISTEN" | "LISTENING")
            && is_probable_minecraft_service_port(connection.local_port)
            && !is_wildcard_ip(&connection.local_addr)
            && !is_loopback_ip(&connection.local_addr)
        {
            let score = if is_lan_ip(&connection.local_addr) {
                6
            } else {
                4
            };
            *scores.entry(connection.local_port).or_default() += score;
        }
    }

    for item in json_items(snapshot.get("Tcp")) {
        let Some(local_port) = json_u16(item, "LocalPort") else {
            continue;
        };
        let Some(pid) = json_u32(item, "OwningProcess") else {
            continue;
        };
        let Some(process) = process_map.get(&pid) else {
            continue;
        };
        if !is_minecraft_client_process(&process.name, &process.command_line) {
            continue;
        }
        let state = json_string(item, "State").to_ascii_uppercase();
        let local_addr = normalize_ip_literal(&json_string(item, "LocalAddress"));
        if matches!(state.as_str(), "LISTEN" | "LISTENING")
            && is_probable_minecraft_service_port(local_port)
            && !is_wildcard_ip(&local_addr)
            && !is_loopback_ip(&local_addr)
        {
            let score = if is_lan_ip(&local_addr) { 4 } else { 2 };
            *scores.entry(local_port).or_default() += score;
        }
    }

    for item in json_items(snapshot.get("Udp")) {
        let Some(local_port) = json_u16(item, "LocalPort") else {
            continue;
        };
        let Some(pid) = json_u32(item, "OwningProcess") else {
            continue;
        };
        let Some(process) = process_map.get(&pid) else {
            continue;
        };
        if !is_minecraft_client_process(&process.name, &process.command_line)
            || !is_probable_minecraft_service_port(local_port)
        {
            continue;
        }
        let local_addr = normalize_ip_literal(&json_string(item, "LocalAddress"));
        if is_wildcard_ip(&local_addr) || is_loopback_ip(&local_addr) {
            continue;
        }
        let score = if is_lan_ip(&local_addr) { 4 } else { 2 };
        *scores.entry(local_port).or_default() += score;
    }

    let mut discovered = scores
        .into_iter()
        .filter(|(port, score)| {
            DEFAULT_MINECRAFT_PORT_HINTS.contains(port) || (*score >= 4 && *port >= 1024)
        })
        .collect::<Vec<_>>();
    discovered.sort_by(|(left_port, left_score), (right_port, right_score)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_port.cmp(right_port))
    });

    let mut ports = Vec::new();
    for (port, _) in discovered {
        if !ports.contains(&port) {
            ports.push(port);
        }
        if ports.len() >= MAX_TRACKED_MINECRAFT_PORTS {
            break;
        }
    }
    ports.sort_unstable();
    ports
}

fn build_proxy_probe_ports(minecraft_ports: &[u16]) -> Vec<u16> {
    let mut ports = STATIC_PROXY_PROBE_PORTS.to_vec();
    for port in minecraft_ports {
        if !ports.contains(port) {
            ports.push(*port);
        }
    }
    ports.sort_unstable();
    ports
}

fn is_probable_minecraft_service_port(port: u16) -> bool {
    port >= 1024 && !matches!(port, 1900 | 5353 | 5355)
}

fn collect_default_gateways(snapshot: &Value, adapters: &[AdapterBlock]) -> HashSet<String> {
    let mut gateways = adapters
        .iter()
        .flat_map(|adapter| adapter.default_gateways.iter())
        .map(|gateway| normalize_ip_literal(gateway))
        .filter(|gateway| !gateway.is_empty())
        .collect::<HashSet<_>>();

    for item in json_items(snapshot.get("NetIPConfiguration")) {
        gateways.extend(json_string_list(item, "IPv4DefaultGateway"));
        gateways.extend(json_string_list(item, "IPv6DefaultGateway"));
    }

    gateways
}

fn collect_udp_minecraft_context(
    snapshot: &Value,
    process_map: &HashMap<u32, ProcessMeta>,
    relevant_pids: &HashSet<u32>,
    probe_ports: &[u16],
) -> Vec<String> {
    let mut details = Vec::new();
    for item in json_items(snapshot.get("Udp")) {
        let Some(local_port) = json_u16(item, "LocalPort") else {
            continue;
        };
        if !probe_ports.contains(&local_port) {
            continue;
        }
        let local_addr = normalize_ip_literal(&json_string(item, "LocalAddress"));
        let pid = json_u32(item, "OwningProcess").unwrap_or(0);
        let process = process_map.get(&pid);
        let proc_name = process.map(|p| p.name.as_str()).unwrap_or("unknown");
        let proc_cmd = process.map(|p| p.command_line.as_str()).unwrap_or("");
        let client_process = is_minecraft_client_process(proc_name, proc_cmd);
        if !relevant_pids.contains(&pid) && !client_process {
            continue;
        }
        if is_loopback_ip(&local_addr) || is_wildcard_ip(&local_addr) {
            continue;
        }
        details.push(format!(
            "Supplemental UDP endpoint on relevant process: {}:{} PID {} {} | {}",
            local_addr,
            local_port,
            pid,
            proc_name,
            truncate_text(proc_cmd, 260)
        ));
    }
    details.sort();
    details.dedup();
    details
}

fn normalize_ip_literal(value: &str) -> String {
    let trimmed = value.trim().trim_matches(['[', ']']);
    let without_zone = trimmed.split('%').next().unwrap_or(trimmed);
    if let Ok(ip) = without_zone.parse::<IpAddr>() {
        ip.to_string()
    } else {
        without_zone.to_string()
    }
}

fn parse_ip_addr_literal(ip: &str) -> Option<IpAddr> {
    normalize_ip_literal(ip).parse::<IpAddr>().ok()
}

fn is_ip_literal(ip: &str) -> bool {
    parse_ip_addr_literal(ip).is_some()
}

fn is_lan_ip(ip: &str) -> bool {
    match parse_ip_addr_literal(ip) {
        Some(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local(),
        Some(IpAddr::V6(v6)) => v6.is_unique_local() || v6.is_unicast_link_local(),
        None => false,
    }
}

fn is_loopback_ip(ip: &str) -> bool {
    match parse_ip_addr_literal(ip) {
        Some(IpAddr::V4(v4)) => v4.is_loopback(),
        Some(IpAddr::V6(v6)) => v6.is_loopback(),
        None => false,
    }
}

fn is_wildcard_ip(ip: &str) -> bool {
    if ip.trim() == "*" {
        return true;
    }
    match parse_ip_addr_literal(ip) {
        Some(IpAddr::V4(v4)) => v4.is_unspecified(),
        Some(IpAddr::V6(v6)) => v6.is_unspecified(),
        None => false,
    }
}

fn is_minecraft_client_process(name: &str, command_line: &str) -> bool {
    let text = format!("{name} {command_line}").to_lowercase();
    if text.contains("faker")
        || text.contains("net.java.faker")
        || text.contains("-jar")
            && (text.contains("\\downloads\\") || text.contains("\\desktop\\"))
            && text.contains(".exe")
    {
        return false;
    }

    [
        "minecraft",
        ".minecraft",
        "net.minecraft",
        "minecraft.launcher",
        "--gamedir",
        "--assetsdir",
        "java.library.path",
        "lwjgl",
        "fabric",
        "forge",
        "legacylauncher",
        "tlauncher",
        "knotclient",
        "lunarclient",
        "badlion",
        "feather",
        "mojangtricksinteldriversforperformance_javaw.exe_minecraft.exe.heapdump",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn handshake_target_matches_remote(handshake_host: &str, remote_addr: &str) -> bool {
    let handshake_host = normalize_ip_literal(handshake_host);
    let remote_addr = normalize_ip_literal(remote_addr);
    if handshake_host.eq_ignore_ascii_case(&remote_addr) {
        return true;
    }
    if handshake_host.eq_ignore_ascii_case("localhost") && is_loopback_ip(&remote_addr) {
        return true;
    }
    if is_loopback_ip(&handshake_host) && is_loopback_ip(&remote_addr) {
        return true;
    }
    false
}

fn extract_ipv4s(value: &str) -> Vec<String> {
    let re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    re.find_iter(value)
        .map(|m| m.as_str().to_string())
        .filter(|ip| is_valid_ipv4(ip))
        .collect()
}

fn is_valid_ipv4(ip: &str) -> bool {
    let mut count = 0;
    for part in ip.split('.') {
        count += 1;
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    count == 4
}

fn is_private_ipv4(ip: &str) -> bool {
    let Some([a, b, _, _]) = parse_ipv4_octets(ip) else {
        return false;
    };
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
}

fn parse_ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let parts = ip
        .split('.')
        .map(|p| p.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() == 4 {
        Some([parts[0], parts[1], parts[2], parts[3]])
    } else {
        None
    }
}

fn normalize_mac_display(mac: &str) -> String {
    let clean = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if clean.len() != 12 {
        return mac.trim().to_string();
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn is_locally_administered_mac(mac: &str) -> bool {
    let clean = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>();
    if clean.len() < 2 {
        return false;
    }
    let Ok(first) = u8::from_str_radix(&clean[0..2], 16) else {
        return false;
    };
    (first & 0x02) != 0 && (first & 0x01) == 0
}

fn process_map_from_snapshot(snapshot: &Value) -> HashMap<u32, ProcessMeta> {
    let mut map = HashMap::new();
    for item in json_items(snapshot.get("Processes")) {
        let meta = process_meta_from_value(item);
        if meta.pid != 0 {
            map.insert(meta.pid, meta);
        }
    }
    map
}

fn neighbor_macs_from_snapshot(snapshot: &Value) -> HashMap<String, HashSet<String>> {
    let mut neighbors = HashMap::<String, HashSet<String>>::new();
    for item in json_items(snapshot.get("NeighborsV4"))
        .into_iter()
        .chain(json_items(snapshot.get("NeighborsV6")).into_iter())
    {
        let ip = normalize_ip_literal(&json_string(item, "IPAddress"));
        let mac = normalize_mac_display(&json_string(item, "LinkLayerAddress"));
        if !is_ip_literal(&ip) || mac.trim().is_empty() {
            continue;
        }
        neighbors.entry(ip).or_default().insert(mac);
    }
    neighbors
}

fn process_meta_from_value(value: &Value) -> ProcessMeta {
    ProcessMeta {
        name: json_string(value, "Name"),
        pid: json_u32(value, "ProcessId").unwrap_or(0),
        path: json_string(value, "ExecutablePath"),
        command_line: json_string(value, "CommandLine"),
    }
}

fn json_items(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(_)) => value.into_iter().collect(),
        _ => Vec::new(),
    }
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn json_string_list(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(normalize_ip_literal)
            .filter(|item| !item.is_empty())
            .collect(),
        Some(Value::String(item)) => {
            let normalized = normalize_ip_literal(item);
            if normalized.is_empty() {
                Vec::new()
            } else {
                vec![normalized]
            }
        }
        _ => Vec::new(),
    }
}

fn json_enabled_flag(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => {
            let lower = text.to_ascii_lowercase();
            lower == "enabled" || lower == "true" || lower == "1" || lower == "yes"
        }
        Some(Value::Number(number)) => number.as_u64().is_some_and(|value| value != 0),
        _ => false,
    }
}

fn summarize_important_bindings(snapshot: &Value, alias: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in ["ms_tcpip6", "ms_server", "ms_msclient", "ms_netbt"] {
        let binding = json_items(snapshot.get("AdapterBindings"))
            .into_iter()
            .find(|item| {
                json_string(item, "Name").eq_ignore_ascii_case(alias)
                    && json_string(item, "ComponentID").eq_ignore_ascii_case(component)
            })?;
        parts.push(format!(
            "{}={}",
            component,
            json_enabled_flag(binding, "Enabled")
        ));
    }
    Some(parts.join(","))
}

fn json_u16(value: &Value, key: &str) -> Option<u16> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
}

fn json_u32(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
}

fn is_self_collection_text(lower: &str) -> bool {
    lower.contains("$needle")
        && lower.contains("get-ciminstance win32_process")
        && lower.contains("get-nettcpconnection")
        && lower.contains("convertto-json")
}

fn print_console_summary(report: &ScanReport) {
    println!("\nResult: {}", report.overall);
    println!(
        "Findings: high={}, medium={}, low={}",
        report
            .findings
            .iter()
            .filter(|f| f.confidence == Confidence::High)
            .count(),
        report
            .findings
            .iter()
            .filter(|f| f.confidence == Confidence::Medium)
            .count(),
        report
            .findings
            .iter()
            .filter(|f| f.confidence == Confidence::Low)
            .count()
    );

    for finding in report.findings.iter().take(12) {
        println!(
            "  [{}] {} - {}",
            finding.confidence.label(),
            finding.category,
            finding.title
        );
        for detail in finding.details.iter().take(2) {
            println!("      {}", truncate_text(detail, 180));
        }
    }
}

fn save_report(report: &ScanReport) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or(std::env::current_dir()?);
    let dir = base.join("results");
    fs::create_dir_all(&dir)?;
    let ts = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let txt_path = dir.join(format!("proxy_bypass_found_{ts}.txt"));
    let json_path = dir.join(format!("proxy_bypass_found_{ts}.json"));
    let log_path = dir.join(format!("proxy_bypass_found_{ts}.log"));
    fs::write(&txt_path, render_text_report(report))?;
    fs::write(&json_path, serde_json::to_string_pretty(report)?)?;
    fs::write(&log_path, render_activity_log(report))?;
    Ok((txt_path, json_path, log_path))
}

fn render_text_report(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", report.module));
    out.push_str(&format!("Started: {}\n", report.started_at));
    out.push_str(&format!("Finished: {}\n", report.finished_at));
    out.push_str(&format!("Duration: {} ms\n", report.duration_ms));
    out.push_str(&format!("Overall: {}\n\n", report.overall));

    out.push_str("Findings\n");
    out.push_str("========\n");
    if report.findings.is_empty() {
        out.push_str("No proxy bypass indicators found.\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "\n[{}] {} - {}\n",
                finding.confidence.label(),
                finding.category,
                finding.title
            ));
            for detail in &finding.details {
                out.push_str(&format!("  - {}\n", detail));
            }
        }
    }

    out.push_str("\nAdapters\n");
    out.push_str("========\n");
    for adapter in &report.adapters {
        out.push_str(&format!(
            "{} | desc={} | mac={} | dhcp={:?} | ipv4={:?} | gw={:?} | dhcp_srv={:?} | dns={:?}\n",
            adapter.name,
            adapter.description,
            adapter.physical_address,
            adapter.dhcp_enabled,
            adapter.ipv4_addresses,
            adapter.default_gateways,
            adapter.dhcp_servers,
            adapter.dns_servers
        ));
    }

    out.push_str("\nARP entries\n");
    out.push_str("===========\n");
    for entry in &report.arp_entries {
        out.push_str(&format!(
            "{} | {} | {} | {}\n",
            entry.interface, entry.ip, entry.mac, entry.kind
        ));
    }

    out.push_str("\nPathping hops\n");
    out.push_str("=============\n");
    for hop in &report.pathping_hops {
        out.push_str(&format!("{} -> {}\n", hop.hop, hop.ip));
    }

    out.push_str("\nSource notes\n");
    out.push_str("============\n");
    for note in &report.source_notes {
        out.push_str(&format!("- {}\n", note));
    }

    out.push_str("\nRaw command output\n");
    out.push_str("==================\n");
    for artifact in &report.raw_commands {
        out.push_str(&format!(
            "\n--- {} | {} ---\n{}\n",
            artifact.name, artifact.command, artifact.output
        ));
    }

    out
}

fn render_activity_log(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "[{}] start {}\n",
        report.module, report.started_at
    ));
    out.push_str(&format!(
        "[{}] finish {}\n",
        report.module, report.finished_at
    ));
    out.push_str(&format!(
        "[{}] overall {}\n\n",
        report.module, report.overall
    ));

    for command in &report.raw_commands {
        out.push_str(&format!("--- {} | {} ---\n", command.name, command.command));
        out.push_str(&command.output);
        if !command.output.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str("--- findings ---\n");
    for finding in &report.findings {
        out.push_str(&format!(
            "[{}] {} | {}\n",
            finding.confidence.label(),
            finding.category,
            finding.title
        ));
        for detail in &finding.details {
            out.push_str(&format!("  - {}\n", detail));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterBlock, CommandArtifact, Finding, LocalConfigArtifact, MIN_FAKER_MEMORY_STRING_HITS,
        NetstatTcp, PacketCaptureAnalysis, PacketTupleStat, ProcessMeta, bridge_exists,
        contains_ascii_case_insensitive, detect_packet_relay_correlation, detect_pktmon,
        detect_same_pc_proxy_chain, discover_minecraft_ports, ipv4_in_same_subnet,
        is_locally_administered_mac, is_vpn_proxy_process_text, normalize_faker_memory_hits,
        parse_arp_entries, parse_gateway_nbtstat, parse_gateway_open_tcp_ports,
        parse_gateway_ping_ttls, parse_ipconfig_adapters, parse_netsh_neighbor_macs,
        parse_netstat_tcp, parse_pathping_hops, parse_portproxy_entries, parse_proxy_config_signal,
        sanitize_nbtstat_output,
    };
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn parses_ipconfig_gateway_and_dhcp() {
        let text = r#"
Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Intel Ethernet
   Physical Address. . . . . . . . . : 02-11-22-33-44-55
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.137.44(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.137.1
   DHCP Server . . . . . . . . . . . : 192.168.137.1
   DNS Servers . . . . . . . . . . . : 192.168.137.1
"#;
        let adapters = parse_ipconfig_adapters(text);
        assert_eq!(adapters.len(), 1);
        assert_eq!(adapters[0].default_gateways, vec!["192.168.137.1"]);
        assert_eq!(adapters[0].dhcp_servers, vec!["192.168.137.1"]);
        assert_eq!(adapters[0].dns_servers, vec!["192.168.137.1"]);
    }

    #[test]
    fn parses_arp_and_laa_mac() {
        let text = r#"
Interface: 192.168.137.44 --- 0x12
  Internet Address      Physical Address      Type
  192.168.137.1         02-11-22-33-44-55     dynamic
"#;
        let entries = parse_arp_entries(text);
        assert_eq!(entries.len(), 1);
        assert!(is_locally_administered_mac(&entries[0].mac));
    }

    #[test]
    fn parses_pathping_hops() {
        let text = r#"
Tracing route to 1.1.1.1 over a maximum of 6 hops
  0  192.168.137.44
  1    1ms     1ms     1ms  192.168.137.1
  2   10ms    10ms    10ms  10.0.0.1
Computing statistics for 50 seconds...
"#;
        let hops = parse_pathping_hops(text);
        assert_eq!(hops[0].ip, "192.168.137.1");
    }

    #[test]
    fn parses_gateway_ping_ttl() {
        let raw = vec![CommandArtifact {
            name: "ping_gateway_192_168_137_1".to_string(),
            command: "ping -n 1 -w 300 192.168.137.1".to_string(),
            output: "Reply from 192.168.137.1: bytes=32 time<1ms TTL=128".to_string(),
        }];
        let ttls = parse_gateway_ping_ttls(&raw);
        assert_eq!(ttls.get("192.168.137.1"), Some(&128));
    }

    #[test]
    fn parses_gateway_open_tcp_ports() {
        let raw = vec![
            CommandArtifact {
                name: "tcp_probe_gateway_192_168_137_1_25565".to_string(),
                command: "tcp_probe remote=192.168.137.1:25565".to_string(),
                output: "open".to_string(),
            },
            CommandArtifact {
                name: "tcp_probe_gateway_192_168_137_1_445".to_string(),
                command: "tcp_probe remote=192.168.137.1:445".to_string(),
                output: "closed: connection refused".to_string(),
            },
        ];
        let ports = parse_gateway_open_tcp_ports(&raw);
        assert_eq!(ports.get("192.168.137.1"), Some(&vec![25565]));
    }

    #[test]
    fn detects_same_subnet_ipv4() {
        assert!(ipv4_in_same_subnet(
            "192.168.137.44",
            "192.168.137.10",
            "255.255.255.0"
        ));
        assert!(!ipv4_in_same_subnet(
            "192.168.137.44",
            "192.168.138.10",
            "255.255.255.0"
        ));
    }

    #[test]
    fn parses_gateway_nbtstat() {
        let raw = vec![CommandArtifact {
            name: "nbtstat_gateway_192_168_137_1".to_string(),
            command: "nbtstat -A 192.168.137.1".to_string(),
            output: r#"
NetBIOS Remote Machine Name Table

    WINHOST       <00>  UNIQUE      Registered
    WORKGROUP     <00>  GROUP       Registered
    WINHOST       <20>  UNIQUE      Registered

    MAC Address = 02-11-22-33-44-55
"#
            .to_string(),
        }];
        let parsed = parse_gateway_nbtstat(&raw);
        let info = parsed.get("192.168.137.1").unwrap();
        assert!(info.workstation_service);
        assert!(info.file_server_service);
        assert_eq!(info.mac.as_deref(), Some("02-11-22-33-44-55"));
    }

    #[test]
    fn strips_useless_zero_ip_nbtstat_blocks() {
        let cleaned = sanitize_nbtstat_output(
            "\r\nПодключение по локальной сети* 10:\r\nNode IpAddress: [0.0.0.0] Scope Id: []\r\n\r\n    Host not found.\r\n\r\nNetBIOS Remote Machine Name Table\r\n\r\n    WINHOST       <00>  UNIQUE      Registered\r\n",
        );
        assert!(!cleaned.contains("0.0.0.0"));
        assert!(cleaned.contains("WINHOST"));
    }

    #[test]
    fn parses_netsh_neighbor_macs() {
        let parsed = parse_netsh_neighbor_macs(
            r#"
Interface 16: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
192.168.0.1                                   f4-de-af-24-52-85  Reachable
192.168.0.39                                  aa-1c-04-10-0a-05  Stale
"#,
        );
        assert!(
            parsed
                .get("192.168.0.1")
                .is_some_and(|macs| macs.contains("F4-DE-AF-24-52-85"))
        );
    }

    #[test]
    fn parses_netsh_neighbor_macs_ipv6() {
        let parsed = parse_netsh_neighbor_macs(
            r#"
Interface 16: Ethernet

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
fe80::1%16                                    f4-de-af-24-52-85  Reachable
"#,
        );
        assert!(
            parsed
                .get("fe80::1")
                .is_some_and(|macs| macs.contains("F4-DE-AF-24-52-85"))
        );
    }

    #[test]
    fn parses_ipv6_netstat_sockets() {
        let parsed = parse_netstat_tcp(
            r#"
  TCP    [fe80::1%12]:25565      [fc00::10]:52000      ESTABLISHED     4242
"#,
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].local_addr, "fe80::1");
        assert_eq!(parsed[0].remote_addr, "fc00::10");
        assert_eq!(parsed[0].local_port, 25565);
        assert_eq!(parsed[0].remote_port, 52000);
    }

    #[test]
    fn parses_portproxy_entries() {
        let entries = parse_portproxy_entries(
            r#"
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
127.0.0.1       25565       192.168.137.1   25565
"#,
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].listen_addr, "127.0.0.1");
        assert_eq!(entries[0].listen_port, 25565);
        assert_eq!(entries[0].connect_addr, "192.168.137.1");
        assert_eq!(entries[0].connect_port, 25565);
    }

    #[test]
    fn bridge_detector_requires_real_bridge_shape() {
        assert!(bridge_exists(
            "",
            "Bridge GUID\n{12345678-ABCD-EF01-2345-6789ABCDEF03}"
        ));
        assert!(!bridge_exists(
            "",
            "The following command was not found: bridge list."
        ));
    }

    #[test]
    fn memory_search_is_case_insensitive() {
        assert!(contains_ascii_case_insensitive(
            b"abc future_hook_X64.DLL xyz",
            b"future_hook_x64.dll"
        ));
    }

    #[test]
    fn faker_memory_hits_require_at_least_three_distinct_strings() {
        let mut hits = normalize_faker_memory_hits(vec![
            "allowDirectConnection".to_string(),
            "routerSpoof".to_string(),
        ]);
        hits.sort();
        hits.dedup();
        assert!(hits.len() < MIN_FAKER_MEMORY_STRING_HITS);

        let mut hits = normalize_faker_memory_hits(vec![
            "allowDirectConnection".to_string(),
            "routerSpoof".to_string(),
            "HttpHostSpoofer".to_string(),
            "routerSpoof".to_string(),
        ]);
        hits.sort();
        hits.dedup();
        assert!(hits.len() >= MIN_FAKER_MEMORY_STRING_HITS);
    }

    #[test]
    fn pktmon_zero_counters_are_not_a_detection() {
        let mut findings: Vec<Finding> = Vec::new();
        detect_pktmon(
            &mut findings,
            "Collected data",
            "JliveF_MC_25565_TCP TCP 25565",
            "Name Counter Direction Packets Bytes\nAdapter Upper Receive 0 0",
            r#"[{"Components":[{"Counters":[{"Inbound":{"Packets":0,"Bytes":0},"Outbound":{"Packets":0,"Bytes":0}}]}]}]"#,
            true,
            &[15000, 25565],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn pktmon_nonzero_proxy_port_counters_are_detected() {
        let mut findings: Vec<Finding> = Vec::new();
        detect_pktmon(
            &mut findings,
            "Collected data",
            "JliveF_MC_25565_TCP TCP 25565",
            "Name Counter Direction Packets Bytes\nAdapter Upper Receive 3 180",
            r#"{"Groups":[{"Components":[{"Counters":[{"Inbound":{"Packets":3,"Bytes":180},"Outbound":{"Packets":0,"Bytes":0}}]}]}]}"#,
            true,
            &[15000, 25565],
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn pktmon_probe_traffic_without_flow_context_is_not_detected() {
        let mut findings: Vec<Finding> = Vec::new();
        detect_pktmon(
            &mut findings,
            "Collected data",
            "JliveF_MC_25565_TCP TCP 25565",
            "Name Counter Direction Packets Bytes\nAdapter Upper Receive 2 120",
            r#"[{"Components":[{"Counters":[{"Inbound":{"Packets":2,"Bytes":120},"Outbound":{"Packets":0,"Bytes":0}}]}]}]"#,
            false,
            &[15000, 25565],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn pktmon_packets_header_without_numeric_hits_is_not_detected() {
        let mut findings: Vec<Finding> = Vec::new();
        detect_pktmon(
            &mut findings,
            "Collected data",
            "JliveF_MC_25565_TCP TCP 25565",
            "Name Counter Direction Packets Bytes\nAdapter Upper Receive Packets Bytes",
            "",
            true,
            &[15000, 25565],
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn discovers_custom_minecraft_port_from_active_java_connection() {
        let entries = vec![NetstatTcp {
            local_addr: "192.168.0.45".to_string(),
            local_port: 52114,
            remote_addr: "192.168.0.50".to_string(),
            remote_port: 25715,
            state: "ESTABLISHED".to_string(),
            pid: 4242,
        }];
        let mut process_map = HashMap::new();
        process_map.insert(
            4242,
            ProcessMeta {
                name: "javaw.exe".to_string(),
                pid: 4242,
                path: "C:\\Games\\Minecraft\\javaw.exe".to_string(),
                command_line: "javaw.exe -jar .minecraft".to_string(),
            },
        );
        let snapshot = json!({
            "Udp": [
                {
                    "LocalAddress": "192.168.0.45",
                    "LocalPort": 25715,
                    "OwningProcess": 4242
                }
            ]
        });

        let ports = discover_minecraft_ports(&entries, &snapshot, &process_map);
        assert!(ports.contains(&25715));
        assert!(ports.contains(&25565));
    }

    #[test]
    fn vpn_process_matcher_avoids_substring_false_hits() {
        assert!(!is_vpn_proxy_process_text(
            r#"searchapp.exe c:\windows\systemapps\microsoft.windows.search\searchapp.exe"#
        ));
        assert!(is_vpn_proxy_process_text(
            r#"happ.exe c:\program files\flyfrogllc\happ\happ.exe"#
        ));
    }

    #[test]
    fn parses_happ_style_proxy_config_signal() {
        let artifact = LocalConfigArtifact {
            path: r#"C:\Users\test\AppData\Local\Happ\config.json"#.to_string(),
            content: r#"{
                "inbounds":[{"type":"tun","interface_name":"happ-tun","address":["172.18.0.1/30"],"auto_route":true,"strict_route":true}],
                "outbounds":[{"type":"socks","server":"127.0.0.1","server_port":10808}],
                "route":{"final":"proxy","rules":[{"process_name":["xray.exe","sing-box.exe"]}]}
            }"#
            .to_string(),
        };
        let signal = parse_proxy_config_signal(&artifact).expect("signal");
        assert!(signal.final_proxy);
        assert!(signal.auto_route);
        assert!(signal.strict_route);
        assert_eq!(signal.tun_interfaces, vec!["happ-tun"]);
        assert_eq!(signal.loopback_proxy_outbounds, vec!["127.0.0.1:10808"]);
    }

    #[test]
    fn parses_happ_style_yaml_proxy_config_signal() {
        let artifact = LocalConfigArtifact {
            path: r#"C:\Users\test\AppData\Local\Happ\config.yaml"#.to_string(),
            content: r#"
inbounds:
  - type: tun
    interface_name: happ-tun
    address:
      - 172.18.0.1/30
    auto_route: true
    strict_route: true
outbounds:
  - type: socks
    server: 127.0.0.1
    server_port: 10808
route:
  final: proxy
  rules:
    - process_name:
        - xray.exe
        - sing-box.exe
"#
            .to_string(),
        };
        let signal = parse_proxy_config_signal(&artifact).expect("yaml signal");
        assert!(signal.final_proxy);
        assert!(signal.auto_route);
        assert!(signal.strict_route);
        assert_eq!(signal.tun_interfaces, vec!["happ-tun"]);
        assert_eq!(signal.loopback_proxy_outbounds, vec!["127.0.0.1:10808"]);
        assert_eq!(
            signal.route_process_names,
            vec!["sing-box.exe".to_string(), "xray.exe".to_string()]
        );
    }

    #[test]
    fn detects_same_pc_proxy_chain_for_tunnel_minecraft_flow() {
        let adapters = vec![AdapterBlock {
            name: "happ-tun".to_string(),
            description: "sing-tun Tunnel".to_string(),
            ipv4_addresses: vec!["172.18.0.1".to_string()],
            default_gateways: vec!["172.18.0.2".to_string()],
            ..AdapterBlock::default()
        }];
        let entries = vec![
            NetstatTcp {
                local_addr: "172.18.0.1".to_string(),
                local_port: 1146,
                remote_addr: "5.231.75.25".to_string(),
                remote_port: 25715,
                state: "ESTABLISHED".to_string(),
                pid: 8208,
            },
            NetstatTcp {
                local_addr: "172.18.0.1".to_string(),
                local_port: 1151,
                remote_addr: "5.231.75.25".to_string(),
                remote_port: 25715,
                state: "ESTABLISHED".to_string(),
                pid: 5732,
            },
            NetstatTcp {
                local_addr: "127.0.0.1".to_string(),
                local_port: 10808,
                remote_addr: "0.0.0.0".to_string(),
                remote_port: 0,
                state: "LISTENING".to_string(),
                pid: 10164,
            },
            NetstatTcp {
                local_addr: "127.0.0.1".to_string(),
                local_port: 25565,
                remote_addr: "0.0.0.0".to_string(),
                remote_port: 0,
                state: "LISTENING".to_string(),
                pid: 5732,
            },
            NetstatTcp {
                local_addr: "127.0.0.1".to_string(),
                local_port: 25565,
                remote_addr: "127.0.0.2".to_string(),
                remote_port: 1145,
                state: "ESTABLISHED".to_string(),
                pid: 5732,
            },
        ];
        let mut process_map = HashMap::new();
        process_map.insert(
            8208,
            ProcessMeta {
                name: "javaw.exe".to_string(),
                pid: 8208,
                path: r#"C:\Games\Minecraft\javaw.exe"#.to_string(),
                command_line: "javaw.exe -jar .minecraft".to_string(),
            },
        );
        process_map.insert(
            5732,
            ProcessMeta {
                name: "javaw.exe".to_string(),
                pid: 5732,
                path: r#"C:\Games\Minecraft\javaw.exe"#.to_string(),
                command_line: "javaw.exe -jar .minecraft proxy-relay".to_string(),
            },
        );
        process_map.insert(
            10164,
            ProcessMeta {
                name: "xray.exe".to_string(),
                pid: 10164,
                path: r#"C:\Program Files\FlyFrogLLC\Happ\core\xray.exe"#.to_string(),
                command_line: r#""C:\Program Files\FlyFrogLLC\Happ\core\xray.exe""#.to_string(),
            },
        );
        let snapshot = json!({
            "Udp": [
                {
                    "LocalAddress": "127.0.0.1",
                    "LocalPort": 10808,
                    "OwningProcess": 10164
                }
            ]
        });
        let configs = vec![LocalConfigArtifact {
            path: r#"C:\Users\test\AppData\Local\Happ\config.json"#.to_string(),
            content: r#"{
                "inbounds":[{"type":"tun","interface_name":"happ-tun","address":["172.18.0.1/30"],"auto_route":true,"strict_route":true}],
                "outbounds":[{"type":"socks","server":"127.0.0.1","server_port":10808}],
                "route":{"final":"proxy","rules":[{"process_name":["xray.exe","sing-box.exe"]}]}
            }"#
            .to_string(),
        }];

        let mut findings = Vec::new();
        detect_same_pc_proxy_chain(
            &mut findings,
            &adapters,
            &snapshot,
            &process_map,
            &entries,
            &[25565, 25715],
            &configs,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.category == "same_pc_proxy_chain"
                    && finding.confidence == super::Confidence::High)
        );
    }

    #[test]
    fn detects_packet_relay_correlation_for_same_upstream_endpoint() {
        let entries = vec![
            NetstatTcp {
                local_addr: "192.168.0.39".to_string(),
                local_port: 3434,
                remote_addr: "5.231.75.25".to_string(),
                remote_port: 25715,
                state: "ESTABLISHED".to_string(),
                pid: 8208,
            },
            NetstatTcp {
                local_addr: "192.168.0.39".to_string(),
                local_port: 3432,
                remote_addr: "5.231.75.25".to_string(),
                remote_port: 25715,
                state: "ESTABLISHED".to_string(),
                pid: 5732,
            },
            NetstatTcp {
                local_addr: "127.0.0.1".to_string(),
                local_port: 24431,
                remote_addr: "0.0.0.0".to_string(),
                remote_port: 0,
                state: "LISTENING".to_string(),
                pid: 5732,
            },
            NetstatTcp {
                local_addr: "127.0.0.1".to_string(),
                local_port: 24431,
                remote_addr: "127.0.0.1".to_string(),
                remote_port: 60000,
                state: "ESTABLISHED".to_string(),
                pid: 5732,
            },
        ];
        let mut process_map = HashMap::new();
        process_map.insert(
            8208,
            ProcessMeta {
                name: "javaw.exe".to_string(),
                pid: 8208,
                path: r#"C:\Games\Minecraft\javaw.exe"#.to_string(),
                command_line: "javaw.exe --gameDir .minecraft".to_string(),
            },
        );
        process_map.insert(
            5732,
            ProcessMeta {
                name: "javaw.exe".to_string(),
                pid: 5732,
                path: r#"C:\Users\test\faker-1.7.exe"#.to_string(),
                command_line: r#""C:\Program Files\Eclipse Adoptium\jdk-21\bin\javaw.exe" -jar "C:\Users\test\faker-1.7.exe""#.to_string(),
            },
        );

        let analysis = PacketCaptureAnalysis {
            total_packets: 40,
            tuples: vec![
                PacketTupleStat {
                    id: "client".to_string(),
                    pid: 8208,
                    process_name: "javaw.exe".to_string(),
                    local_addr: "192.168.0.39".to_string(),
                    local_port: 3434,
                    remote_addr: "5.231.75.25".to_string(),
                    remote_port: 25715,
                    outbound_packets: 8,
                    inbound_packets: 9,
                    outbound_payload_bytes: 240,
                    inbound_payload_bytes: 280,
                    syn_out: 1,
                    syn_in: 0,
                    fin_out: 0,
                    fin_in: 0,
                    rst_out: 0,
                    rst_in: 0,
                    ack_out: 7,
                    ack_in: 9,
                    ttl_in_values: vec![50],
                    ttl_out_values: vec![128],
                    first_time: Some(1.0),
                    last_time: Some(3.4),
                    duration: 2.4,
                    minecraft_handshake_host: Some("funtime.su".to_string()),
                    minecraft_handshake_port: Some(25715),
                    minecraft_handshake_protocol: Some(769),
                    minecraft_handshake_state: Some(2),
                },
                PacketTupleStat {
                    id: "relay".to_string(),
                    pid: 5732,
                    process_name: "javaw.exe".to_string(),
                    local_addr: "192.168.0.39".to_string(),
                    local_port: 3432,
                    remote_addr: "5.231.75.25".to_string(),
                    remote_port: 25715,
                    outbound_packets: 7,
                    inbound_packets: 8,
                    outbound_payload_bytes: 220,
                    inbound_payload_bytes: 260,
                    syn_out: 1,
                    syn_in: 0,
                    fin_out: 0,
                    fin_in: 0,
                    rst_out: 0,
                    rst_in: 0,
                    ack_out: 6,
                    ack_in: 8,
                    ttl_in_values: vec![50],
                    ttl_out_values: vec![128],
                    first_time: Some(1.1),
                    last_time: Some(3.5),
                    duration: 2.4,
                    minecraft_handshake_host: Some("funtime.su".to_string()),
                    minecraft_handshake_port: Some(25715),
                    minecraft_handshake_protocol: Some(769),
                    minecraft_handshake_state: Some(2),
                },
            ],
            endpoints: Vec::new(),
        };

        let mut findings = Vec::new();
        detect_packet_relay_correlation(
            &mut findings,
            &process_map,
            &entries,
            &[25565, 25715],
            Some(&analysis),
        );

        assert!(findings.iter().any(|finding| {
            finding.category == "packet_relay_correlation"
                && finding.confidence == super::Confidence::High
        }));
    }
}
