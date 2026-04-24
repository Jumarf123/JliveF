use serde::Serialize;
use std::path::PathBuf;
use windows::Win32::Foundation::HANDLE;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ScanReport {
    pub(crate) module: String,
    pub(crate) started_at: String,
    pub(crate) finished_at: String,
    pub(crate) duration_ms: u128,
    pub(crate) overall: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) adapters: Vec<AdapterBlock>,
    pub(crate) arp_entries: Vec<ArpEntry>,
    pub(crate) pathping_hops: Vec<PathHop>,
    pub(crate) raw_commands: Vec<CommandArtifact>,
    pub(crate) source_notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Finding {
    pub(crate) confidence: Confidence,
    pub(crate) category: String,
    pub(crate) title: String,
    pub(crate) details: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }

    pub(crate) fn score(&self) -> u8 {
        match self {
            Confidence::High => 3,
            Confidence::Medium => 2,
            Confidence::Low => 1,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct AdapterBlock {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) physical_address: String,
    pub(crate) dhcp_enabled: Option<bool>,
    pub(crate) ipv4_addresses: Vec<String>,
    pub(crate) subnet_masks: Vec<String>,
    pub(crate) default_gateways: Vec<String>,
    pub(crate) dhcp_servers: Vec<String>,
    pub(crate) dns_servers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ArpEntry {
    pub(crate) interface: String,
    pub(crate) ip: String,
    pub(crate) mac: String,
    pub(crate) kind: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PathHop {
    pub(crate) hop: u32,
    pub(crate) ip: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CommandArtifact {
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) output: String,
}

#[derive(Clone, Copy)]
pub(crate) struct ParallelCommandSpec {
    pub(crate) name: &'static str,
    pub(crate) exe: &'static str,
    pub(crate) args: &'static [&'static str],
}

#[derive(Clone, Debug)]
pub(crate) struct NetstatTcp {
    pub(crate) local_addr: String,
    pub(crate) local_port: u16,
    pub(crate) remote_addr: String,
    pub(crate) remote_port: u16,
    pub(crate) state: String,
    pub(crate) pid: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessMeta {
    pub(crate) name: String,
    pub(crate) pid: u32,
    pub(crate) path: String,
    pub(crate) command_line: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NbtstatInfo {
    pub(crate) names: Vec<String>,
    pub(crate) workstation_service: bool,
    pub(crate) file_server_service: bool,
    pub(crate) mac: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct PortProxyEntry {
    pub(crate) listen_addr: String,
    pub(crate) listen_port: u16,
    pub(crate) connect_addr: String,
    pub(crate) connect_port: u16,
}

#[derive(Clone)]
pub(crate) struct ModuleInfo {
    pub(crate) path: PathBuf,
}

pub(crate) struct HandleGuard(pub(crate) HANDLE);
