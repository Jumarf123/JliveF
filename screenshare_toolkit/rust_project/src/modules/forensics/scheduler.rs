use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::Result;

use crate::core::parsers::{detect_special_extension_fragment, extract_windows_paths};
use crate::core::report::ModuleReport;
use crate::core::signatures::is_trusted;

use crate::modules::processes::memory_tool;

pub fn run(report: &mut ModuleReport) -> Result<()> {
    let Some(pid) = memory_tool::get_service_pid("Schedule")? else {
        report.add_warning(
            "Task Scheduler service not found",
            "The Schedule service did not expose a ProcessId.",
        );
        return Ok(());
    };

    let mut seen_paths = HashSet::new();
    let mut previous = String::new();

    memory_tool::scan_pid_lines(pid, |line| {
        let trimmed = line.trim();
        if detect_special_extension_fragment(&previous, trimmed) {
            report.add_warning(
                "Scheduler special-character execution pattern",
                format!("Path fragment=`{previous}` extension=`{trimmed}`"),
            );
        }

        for path in extract_windows_paths(trimmed) {
            if !seen_paths.insert(path.clone()) {
                continue;
            }

            let path_buf = PathBuf::from(&path);
            if path_buf.exists() {
                if !is_trusted(&path_buf)? {
                    report.add_warning(
                        "Unsigned file in Scheduler memory",
                        format!("{} (PID {})", path_buf.display(), pid),
                    );
                }
            } else {
                report.add_warning(
                    "Deleted file trace in Scheduler memory",
                    format!("{path} (PID {pid})"),
                );
            }
        }

        previous = trimmed.to_string();
        Ok(())
    })?;

    Ok(())
}
