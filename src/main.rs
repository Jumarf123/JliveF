//! Internal JVM class dumper CLI for Windows 10/11.

use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

mod bypass_scan;
mod dump_report;
mod external_dumper;
#[path = "external_dumper_New/mod.rs"]
mod external_dumper_new;
mod found_faker;
mod internal_dumper;
mod jvmti_detector;
mod netscan;
mod proxy_bypass_found;
mod script_finder;
mod winliveinfo;

fn main() {
    if let Err(error) = run_app() {
        display_error_and_wait("JliveF failed", &error.to_string());
        std::process::exit(1);
    }
}

fn run_app() -> Result<()> {
    require_admin()?;

    if std::env::var("JLIVEF_MODE").as_deref() == Ok("winliveinfo") {
        return winliveinfo::run_winliveinfo().map_err(|e| anyhow!("WinLiveInfo failed: {e}"));
    }

    loop {
        println!("\nJlivef");
        println!("1) Dumper");
        println!("2) Network Scanner");
        println!("3) WinLiveInfo (Live system viewer)");
        println!("4) JVMTI detector");
        println!("5) Found Faker");
        println!("6) Bypass Scanner");
        println!("7) Script Launch Finder");
        println!("8) Screenshare Toolkit");
        println!("9) proxy bypass found (beta-test)");
        println!("10) Exit");
        print!("Select option: ");
        io::stdout().flush().ok();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let action = match choice.trim() {
            "1" => internal_dumper::run_dumper(),
            "2" => {
                netscan::run_scan_flow();
                Ok(())
            }
            "3" => run_winliveinfo_ui(),
            "4" => jvmti_detector::run_detector_cli(),
            "5" => found_faker::run_found_faker(),
            "6" => bypass_scan::run_bypass_scan_flow(),
            "7" => script_finder::run_script_launch_finder(),
            "8" => run_screenshare_toolkit(),
            "9" => proxy_bypass_found::run_proxy_bypass_found(),
            "10" => {
                println!("Bye.");
                break;
            }
            other => {
                println!("Unknown option: {other}");
                continue;
            }
        };

        if let Err(error) = action {
            display_error_and_wait("Operation failed", &format!("{error:#}"));
        }
    }

    Ok(())
}

fn run_winliveinfo_ui() -> Result<()> {
    println!("Launching WinLiveInfo UI in a separate process...");
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.env("JLIVEF_MODE", "winliveinfo");
    cmd.spawn()
        .map_err(|e| anyhow!("Failed to spawn WinLiveInfo process: {e}"))?;
    println!("WinLiveInfo started. Close its window to return to the menu.");
    Ok(())
}

fn run_screenshare_toolkit() -> Result<()> {
    screenshare_toolkit::app::run().map_err(|e| anyhow!("Screenshare Toolkit failed: {e}"))?;
    println!("Returned from Screenshare Toolkit.");
    Ok(())
}

fn is_administrator() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

fn require_admin() -> Result<()> {
    if is_administrator() {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let to_wide = |s: &OsStr| {
        s.encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let exe_w = to_wide(exe.as_os_str());
    let verb = to_wide(OsStr::new("runas"));

    let res = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    if res.0 <= 32 {
        return Err(anyhow!(
            "Не удалось запросить повышение прав (ShellExecuteW), код {}",
            res.0
        ));
    }

    std::process::exit(0);
}

fn display_error_and_wait(title: &str, body: &str) {
    eprintln!("\n{title}");
    eprintln!("{body}");
    eprintln!("\nPress Enter to continue...");
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
}
