use super::*;

pub(super) fn is_vpn_proxy_process_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let tokens = [
        "happ.exe",
        "xray.exe",
        "sing-box",
        "singbox",
        "clash",
        "v2ray",
        "v2rayn",
        "v2rayng",
        "wireguard",
        "wg.exe",
        "openvpn",
        "tailscale",
        "zerotier",
        "radmin vpn",
        "hamachi",
        "protonvpn",
        "nordvpn",
        "surfshark",
        "mullvad",
        "outline",
        "hiddify",
        "nekoray",
        "tun2socks",
        "tun2proxy",
        "tun.exe",
        "wintun",
        "fake tcp",
        "faker",
    ];
    tokens.iter().any(|token| lower.contains(token))
}

pub(super) fn is_virtualish_adapter(adapter: &AdapterBlock) -> bool {
    let text = format!("{} {}", adapter.name, adapter.description).to_ascii_lowercase();
    let markers = [
        "vpn",
        "virtual",
        "loopback",
        "wintun",
        "wireguard",
        "hamachi",
        "radmin",
        "tap-",
        "tun",
        "hyper-v",
        "vmware",
        "virtualbox",
        "npcap",
        "tailscale",
        "zerotier",
        "happ",
        "xray",
        "sing",
        "clash",
    ];
    markers.iter().any(|marker| text.contains(marker))
}
