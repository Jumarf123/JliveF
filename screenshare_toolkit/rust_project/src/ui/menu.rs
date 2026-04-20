use std::io::{self, Write};

use anyhow::{Result, bail};

use crate::core::report::ModuleDescriptor;

pub enum MenuAction {
    Exit,
    Run(u8),
}

pub fn prompt_main_menu(catalog: &[ModuleDescriptor]) -> Result<MenuAction> {
    println!("Select a module:");
    for descriptor in catalog {
        println!("  {}. {}", descriptor.id, descriptor.label);
    }
    println!("  4. Return to JliveF");
    print!("\nEnter a number: ");
    io::stdout().flush()?;

    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Ok(MenuAction::Exit);
    }
    let trimmed = input.trim();

    if trimmed == "4" {
        return Ok(MenuAction::Exit);
    }

    let choice = trimmed
        .parse::<u8>()
        .map_err(|_| anyhow::anyhow!("expected a number from 1 to 4, got `{trimmed}`"))?;

    if catalog.iter().any(|descriptor| descriptor.id == choice) {
        Ok(MenuAction::Run(choice))
    } else {
        bail!("module `{choice}` is not in the menu")
    }
}

pub fn wait_for_enter() -> Result<()> {
    println!("\nPress Enter to return to the menu...");
    let mut buffer = String::new();
    let _ = io::stdin().read_line(&mut buffer)?;
    Ok(())
}
