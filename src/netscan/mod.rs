use colored::Colorize;
use colored::control::{set_override, set_virtual_terminal};
use std::io;

pub mod netsh;
pub mod registry;
pub mod report;
pub mod rules;

/// Run the network scan workflow and print results.
pub fn run_scan_flow() {
    init_colors();
    print_admin_status();

    println!("Идёт сканирование...");
    println!("- Реестр: Interfaces");
    println!("- Реестр: Tcpip\\Parameters");
    println!("- Реестр: Class сетевых адаптеров");
    println!("- Реестр: Enum\\PCI MSI");
    println!("- Реестр: Multimedia\\SystemProfile");
    println!("- Реестр: AFD\\Parameters");
    println!("- Команда: netsh int tcp show global");

    let report = rules::run_all_scans();
    report.print();

    println!("Нажмите Enter чтобы вернуться в меню");
    let mut dummy = String::new();
    let _ = io::stdin().read_line(&mut dummy);
}

fn init_colors() {
    #[cfg(windows)]
    {
        if !set_virtual_terminal(true).is_ok() {
            set_override(false);
        }
    }
}

fn is_admin() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

fn print_admin_status() {
    let status = if is_admin() { "Да" } else { "Нет" };
    println!("Запуск с правами администратора: {}", status.bold());
}
