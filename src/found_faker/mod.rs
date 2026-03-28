mod admin;
mod models;
mod report;
mod scanner;
mod viewer;

use anyhow::Result;
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run_found_faker() -> Result<()> {
    admin::ensure_admin();
    print_banner();

    // Defaults from original CLI.
    let hours_back = 24;
    let verbose = false;

    println!("Running Found Faker scan (last {hours_back}h)...");
    let scan_handle = std::thread::spawn(move || scanner::run_scan(hours_back, verbose));
    let scan = match scan_handle.join() {
        Ok(res) => res,
        Err(_) => {
            eprintln!("Scan thread failed.");
            return Ok(());
        }
    };

    let report_name = scanner::generate_random_report_name();
    let mut output_path = exe_dir_path().unwrap_or_else(|| std::env::current_dir().unwrap());
    output_path.push(report_name);

    match report::save_report(&scan, &output_path) {
        Ok(_) => println!("Report saved: {}", output_path.display()),
        Err(err) => {
            eprintln!("Error saving report: {err}");
            return Ok(());
        }
    }

    print_summary(&scan);
    if scan.connected_devices.len() >= 2 && !scan.possible_variables {
        println!("Note: Multiple devices detected - review ARP table in report");
    }
    println!("Opening report in embedded viewer...");

    let view_path = output_path.clone();
    let view_handle = std::thread::spawn(move || viewer::open_report(&view_path));
    match view_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("Could not open embedded viewer: {err}");
            eprintln!("WebView2 runtime may be missing. Please install it and try again.");
        }
        Err(_) => {
            eprintln!("Viewer thread panicked.");
        }
    }

    pause_for_enter();
    Ok(())
}

fn print_banner() {
    println!(
        r#"
                                                 
 _    _       _          ___     _               
|_|  | |_ ___| |_ ___   |  _|___| |_ ___ ___ ___ 
| |  |   | .'|  _| -_|  |  _| .'| '_| -_|  _|_ -|
|_|  |_|_|__,|_| |___|  |_| |__,|_,_|___|_| |___|
                                                 
Searching for Fakers!
"#
    );
    println!("Hotspot Detections for Fakers");
    println!("Made with love by lily<3\n");
}

fn exe_dir_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

fn print_summary(scan: &models::ScanResult) {
    use models::NetworkProfile;
    let hotspot_profiles = scan
        .network_profiles
        .iter()
        .filter(|p: &&NetworkProfile| p.is_hotspot)
        .count();

    println!("\nSUMMARY:");
    println!(
        "  Suspicious Activities: {}",
        scan.suspicious_activities.len()
    );
    println!("  Hotspot Profiles: {}", hotspot_profiles);
    println!(
        "  Hosted Network: {}",
        if scan.hosted_network.active {
            "ACTIVE"
        } else {
            "Inactive"
        }
    );
    println!(
        "  Mobile Hotspot: {}",
        if scan.mobile_hotspot_active {
            "RUNNING"
        } else {
            "Stopped"
        }
    );
    println!("  Virtual Adapters: {}", scan.virtual_adapters.len());
    println!("  Connected Devices: {}", scan.connected_devices.len());

    if !scan.suspicious_activities.is_empty() {
        println!("\nWARNINGS:");
        for activity in &scan.suspicious_activities {
            println!("  - {activity}");
        }
    }
}

fn pause_for_enter() {
    print!("Press Enter to return to menu...");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    let _ = io::stdin().read_line(&mut buf);
}
