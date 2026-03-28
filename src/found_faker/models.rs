use chrono::{DateTime, Local};

#[derive(Clone, Debug, Default)]
pub struct WlanEvent {
    pub time_created: DateTime<Local>,
    pub event_id: u32,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkProfile {
    pub ssid: String,
    pub is_hotspot: bool,
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct CurrentConnection {
    pub ssid: String,
    pub state: String,
    pub bssid: String,
    pub network_type: String,
    pub radio_type: String,
    pub channel: String,
    pub signal: String,
    pub is_hotspot: bool,
    pub hotspot_indicators: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct HostedNetwork {
    pub active: bool,
    pub ssid: String,
    pub clients: u32,
}

impl Default for HostedNetwork {
    fn default() -> Self {
        Self {
            active: false,
            ssid: "N/A".to_string(),
            clients: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct VirtualAdapter {
    pub name: String,
    pub description: String,
    pub mac: String,
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct ConnectedDevice {
    pub ip: String,
    pub mac: String,
    pub device_type: String,
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct ScanResult {
    pub start_time: DateTime<Local>,
    pub hours_back: i64,
    pub suspicious_activities: Vec<String>,
    pub faker_detected: bool,
    pub faker_indicators: Vec<String>,
    pub wlan_events: Vec<WlanEvent>,
    pub network_profiles: Vec<NetworkProfile>,
    pub current_connection: Option<CurrentConnection>,
    pub hosted_network: HostedNetwork,
    pub mobile_hotspot_active: bool,
    pub virtual_adapters: Vec<VirtualAdapter>,
    pub connected_devices: Vec<ConnectedDevice>,
    pub possible_variables: bool,
}
