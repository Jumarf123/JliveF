use std::io;

use anyhow::Result;
use crossterm::style::{Color, Stylize};

use crate::core::report::{ModuleReport, Severity};
use crate::core::time::format_datetime;

pub fn print_banner() {
    println!();
    println!("{}", "Screenshare Toolkit".with(Color::Cyan));
    println!();
}

pub fn print_report(report: &ModuleReport) -> Result<()> {
    let (info, warning, critical) = report.counts();
    let started = format_datetime(&report.started_at);
    let finished = report
        .finished_at
        .as_ref()
        .map(format_datetime)
        .unwrap_or_else(|| "n/a".to_string());

    println!(
        "{}",
        format!(
            "Module {}: {}",
            report.descriptor.id, report.descriptor.label
        )
        .with(Color::Blue)
    );
    println!("Started: {started}");
    println!("Finished: {finished}");
    println!("Summary: info={info}, warning={warning}, critical={critical}");
    println!();

    if report.findings.is_empty() {
        println!("{}", "No findings.".with(Color::Green));
    } else {
        for finding in &report.findings {
            let severity = match finding.severity {
                Severity::Info => "[INFO]".with(Color::Blue),
                Severity::Warning => "[WARN]".with(Color::Yellow),
                Severity::Critical => "[CRIT]".with(Color::Red),
            };
            println!("{severity} {}", finding.title);
            println!("       {}", finding.detail);
        }
    }

    io::Write::flush(&mut io::stdout())?;
    Ok(())
}
