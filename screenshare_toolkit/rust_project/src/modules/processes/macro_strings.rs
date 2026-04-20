use anyhow::Result;
use regex::Regex;

use crate::core::report::ModuleReport;

use super::memory_tool;

enum PatternKind {
    Literal(&'static str),
    Regex(&'static str),
}

struct MacroPattern {
    process_name: &'static str,
    label: &'static str,
    pattern: PatternKind,
}

const PATTERNS: &[MacroPattern] = &[
    MacroPattern {
        process_name: "lghub_agent.exe",
        label: "Logitech deleted macro trace",
        pattern: PatternKind::Regex(r#"durationms.+\"isDown\""#),
    },
    MacroPattern {
        process_name: "Razer Synapse.exe",
        label: "Razer delete trace",
        pattern: PatternKind::Literal("DeleteMacroEvent"),
    },
    MacroPattern {
        process_name: "Razer Synapse 3.exe",
        label: "Razer speed setting",
        pattern: PatternKind::Literal("SetKeysPerSecond"),
    },
    MacroPattern {
        process_name: "RazerCentralService.exe",
        label: "Razer macro sync trace",
        pattern: PatternKind::Literal("Datasync: Status: COMPLETE Action: NONE Macros/"),
    },
    MacroPattern {
        process_name: "SteelSeriesGGClient.exe",
        label: "SteelSeries deleted macro trace",
        pattern: PatternKind::Regex(r#"delay.+is_deleted"#),
    },
    MacroPattern {
        process_name: "Onikuma.exe",
        label: "Onikuma macro string",
        pattern: PatternKind::Literal("LeftKey CODE:"),
    },
];

pub fn run(report: &mut ModuleReport) -> Result<()> {
    for pattern in PATTERNS {
        let processes = memory_tool::get_processes_by_names(&[pattern.process_name])?;
        for process in processes {
            let Some(pid) = process.ProcessId else {
                continue;
            };
            let output = memory_tool::scan_pid(pid)?;
            let matched = match pattern.pattern {
                PatternKind::Literal(needle) => output.contains(needle),
                PatternKind::Regex(expression) => Regex::new(expression)
                    .map(|regex| regex.is_match(&output))
                    .unwrap_or(false),
            };

            if matched {
                report.add_warning(
                    format!("Macro string in {}", pattern.process_name),
                    format!("{} (PID {}).", pattern.label, pid),
                );
            }
        }
    }

    Ok(())
}
