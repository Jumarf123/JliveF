use super::models::HostedNetwork;
use super::models::ScanResult;
use chrono::Local;
use std::fs;
use std::path::Path;

pub fn save_report(scan: &ScanResult, path: &Path) -> anyhow::Result<()> {
    let html = render_report(scan);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, html)?;
    Ok(())
}

fn render_report(scan: &ScanResult) -> String {
    let generated = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut html = String::new();
    html.push_str(r#"<!DOCTYPE html>
<html>
<head>
    <title>WiFi Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; margin-top: 30px; }
        .warning { background: #e74c3c; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .success { background: #27ae60; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .info { background: #3498db; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }
        th { background: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .hotspot-row { background: #ffebee; }
    </style>
</head>
<body>
    <h1>Hotspot detections for Fakers, (DM @praiselily if anything breaks)</h1>
"#);
    html.push_str(&format!("<p>Generated: {generated}</p>"));

    html.push_str("<h2>Suspicious Activities</h2>");
    if !scan.suspicious_activities.is_empty() {
        html.push_str(&format!(
            "<div class='warning'><strong>ALERT: {} suspicious activity(ies) detected!</strong><ul>",
            scan.suspicious_activities.len()
        ));
        for activity in &scan.suspicious_activities {
            html.push_str(&format!("<li>{}</li>", html_escape(activity)));
        }
        html.push_str("</ul></div>");
    } else {
        html.push_str("<div class='success'>No suspicious activities detected</div>");
    }

    if let Some(conn) = &scan.current_connection {
        html.push_str("<h2>Current Connection</h2>");
        if conn.is_hotspot && !scan.possible_variables {
            html.push_str(&format!(
                "<div class='warning'><strong>WARNING: CONNECTED TO HOTSPOT: {}</strong><br>",
                html_escape(&conn.ssid)
            ));
            html.push_str(&format!(
                "BSSID: {}<br>Channel: {} | Signal: {}<br><br>",
                html_escape(&conn.bssid),
                html_escape(&conn.channel),
                html_escape(&conn.signal)
            ));
            if !conn.hotspot_indicators.is_empty() {
                html.push_str("<strong>Hotspot Indicators:</strong><ul>");
                for ind in &conn.hotspot_indicators {
                    html.push_str(&format!("<li>{}</li>", html_escape(ind)));
                }
                html.push_str("</ul>");
            }
            html.push_str("</div>");
        } else {
            html.push_str(&format!(
                "<div class='info'>Connected to: <strong>{}</strong><br>BSSID: {} | Channel: {} | Signal: {}</div>",
                html_escape(&conn.ssid),
                html_escape(&conn.bssid),
                html_escape(&conn.channel),
                html_escape(&conn.signal)
            ));
        }
    }

    html.push_str("<h2>Hosted Network Status</h2>");
    render_hosted_network(&mut html, &scan.hosted_network);

    html.push_str("<h2>Mobile Hotspot Service</h2>");
    if scan.mobile_hotspot_active {
        html.push_str("<div class='warning'>RUNNING</div>");
    } else {
        html.push_str("<div class='success'>Stopped</div>");
    }

    html.push_str("<h2>Network Profiles</h2><table><tr><th>SSID</th><th>Type</th></tr>");
    for profile in &scan.network_profiles {
        let row_class = if profile.is_hotspot {
            " class='hotspot-row'"
        } else {
            ""
        };
        let t = if profile.is_hotspot {
            "HOTSPOT"
        } else {
            "WiFi"
        };
        html.push_str(&format!(
            "<tr{row_class}><td>{}</td><td>{}</td></tr>",
            html_escape(&profile.ssid),
            t
        ));
    }
    html.push_str("</table>");

    if !scan.virtual_adapters.is_empty() {
        html.push_str("<h2>Virtual Adapters</h2><table><tr><th>Description</th><th>MAC</th></tr>");
        for adapter in &scan.virtual_adapters {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(&adapter.description),
                html_escape(&adapter.mac)
            ));
        }
        html.push_str("</table>");
    }

    html.push_str(
        "<h2>Connected Devices</h2><table><tr><th>IP Address</th><th>MAC Address</th></tr>",
    );
    for dev in &scan.connected_devices {
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(&dev.ip),
            html_escape(&dev.mac)
        ));
    }
    html.push_str("</table>");

    if !scan.wlan_events.is_empty() {
        html.push_str("<h2>WLAN Events (last 24h)</h2><table><tr><th>Time</th><th>EventID</th><th>Message</th></tr>");
        for ev in &scan.wlan_events {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                ev.time_created.format("%Y-%m-%d %H:%M:%S"),
                ev.event_id,
                html_escape(&ev.message)
            ));
        }
        html.push_str("</table>");
    }

    html.push_str("</body></html>");
    html
}

fn render_hosted_network(html: &mut String, hosted: &HostedNetwork) {
    if hosted.active {
        html.push_str(&format!(
            "<div class='warning'>ACTIVE - SSID: {}, Clients: {}</div>",
            html_escape(&hosted.ssid),
            hosted.clients
        ));
    } else {
        html.push_str("<div class='success'>Inactive</div>");
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
