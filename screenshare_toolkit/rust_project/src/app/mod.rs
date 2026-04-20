use anyhow::Result;

use crate::core::report::write_text_report;
use crate::modules;
use crate::ui::menu::{MenuAction, prompt_main_menu, wait_for_enter};
use crate::ui::render::{print_banner, print_report};

pub fn run() -> Result<()> {
    crate::core::console::configure();

    loop {
        crate::core::console::configure();
        print_banner();
        let action = match prompt_main_menu(&modules::catalog()) {
            Ok(action) => action,
            Err(error) => {
                eprintln!("Menu error: {error:#}");
                wait_for_enter()?;
                continue;
            }
        };

        match action {
            MenuAction::Exit => break,
            MenuAction::Run(module_id) => {
                crate::core::console::configure();
                match modules::run(module_id) {
                    Ok(mut report) => {
                        let report_dir = write_text_report(&report)?;
                        report.add_info("Report created here", report_dir.display().to_string());
                        write_text_report(&report)?;
                        crate::core::console::configure();
                        print_report(&report)?;
                    }
                    Err(error) => eprintln!("Module error: {error:#}"),
                }
                crate::core::console::configure();
                wait_for_enter()?;
            }
        }
    }

    Ok(())
}
