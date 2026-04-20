use chrono::{DateTime, Local};
use std::path::PathBuf;

use anyhow::Result;

use crate::core::paths::module_results_dir;
use crate::core::text::write_utf8_bom;
use crate::core::time::format_datetime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Clone, Copy, Debug)]
pub struct ModuleDescriptor {
    pub id: u8,
    pub label: &'static str,
    pub summary: &'static str,
}

#[derive(Debug)]
pub struct ModuleReport {
    pub descriptor: ModuleDescriptor,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub started_at: DateTime<Local>,
    pub finished_at: Option<DateTime<Local>>,
}

impl ModuleReport {
    pub fn new(descriptor: ModuleDescriptor) -> Self {
        Self {
            descriptor,
            findings: Vec::new(),
            notes: Vec::new(),
            started_at: Local::now(),
            finished_at: None,
        }
    }

    pub fn add_finding(
        &mut self,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.findings.push(Finding {
            severity,
            title: title.into(),
            detail: detail.into(),
        });
    }

    pub fn add_info(&mut self, title: impl Into<String>, detail: impl Into<String>) {
        self.add_finding(Severity::Info, title, detail);
    }

    pub fn add_warning(&mut self, title: impl Into<String>, detail: impl Into<String>) {
        self.add_finding(Severity::Warning, title, detail);
    }

    pub fn add_critical(&mut self, title: impl Into<String>, detail: impl Into<String>) {
        self.add_finding(Severity::Critical, title, detail);
    }

    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    pub fn merge(&mut self, mut other: ModuleReport) {
        self.findings.append(&mut other.findings);
        self.notes.append(&mut other.notes);
    }

    pub fn finish(mut self) -> Self {
        self.finished_at = Some(Local::now());
        self
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut info = 0;
        let mut warning = 0;
        let mut critical = 0;

        for finding in &self.findings {
            match finding.severity {
                Severity::Info => info += 1,
                Severity::Warning => warning += 1,
                Severity::Critical => critical += 1,
            }
        }

        (info, warning, critical)
    }
}

pub fn write_text_report(report: &ModuleReport) -> Result<PathBuf> {
    let module_dir = module_results_dir(report.descriptor.id, report.descriptor.label)?;
    let report_path = module_dir.join("report.txt");
    write_utf8_bom(&report_path, &render_text_report(report))?;
    Ok(module_dir)
}

fn render_text_report(report: &ModuleReport) -> String {
    let (info, warning, critical) = report.counts();
    let started = format_datetime(&report.started_at);
    let finished = report
        .finished_at
        .as_ref()
        .map(format_datetime)
        .unwrap_or_else(|| "n/a".to_string());

    let mut output = String::new();
    output.push_str("Summary\n");
    output.push_str(&render_table(
        &["Field", "Value"],
        &[
            vec!["Module".to_string(), report.descriptor.label.to_string()],
            vec!["Started".to_string(), started],
            vec!["Finished".to_string(), finished],
            vec!["Info".to_string(), info.to_string()],
            vec!["Warning".to_string(), warning.to_string()],
            vec!["Critical".to_string(), critical.to_string()],
        ],
    ));

    output.push('\n');
    output.push_str("Findings\n");
    if report.findings.is_empty() {
        output.push_str(&render_table(
            &["Level", "Title", "Detail"],
            &[vec![
                "INFO".to_string(),
                "No findings".to_string(),
                "-".to_string(),
            ]],
        ));
    } else {
        let rows = report
            .findings
            .iter()
            .map(|finding| {
                vec![
                    severity_label(finding.severity).to_string(),
                    finding.title.clone(),
                    finding.detail.clone(),
                ]
            })
            .collect::<Vec<_>>();
        output.push_str(&render_table(&["Level", "Title", "Detail"], &rows));
    }

    if !report.notes.is_empty() {
        output.push('\n');
        output.push_str("Notes\n");
        let rows = report
            .notes
            .iter()
            .enumerate()
            .map(|(index, note)| vec![(index + 1).to_string(), note.clone()])
            .collect::<Vec<_>>();
        output.push_str(&render_table(&["#", "Note"], &rows));
    }

    output
}

fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let column_count = headers.len();
    let mut widths = headers
        .iter()
        .map(|header| cell_len(header))
        .collect::<Vec<_>>();

    for row in rows {
        for (index, value) in row.iter().take(column_count).enumerate() {
            widths[index] = widths[index].max(cell_len(&sanitize_cell(value)));
        }
    }

    let mut output = String::new();
    output.push_str(&render_row(
        &headers
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>(),
        &widths,
    ));
    output.push('\n');
    output.push_str(
        &widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("-+-"),
    );
    output.push('\n');

    for row in rows {
        let padded = (0..column_count)
            .map(|index| row.get(index).cloned().unwrap_or_else(|| "-".to_string()))
            .collect::<Vec<_>>();
        output.push_str(&render_row(&padded, &widths));
        output.push('\n');
    }

    output
}

fn render_row(values: &[String], widths: &[usize]) -> String {
    values
        .iter()
        .zip(widths.iter())
        .map(|(value, width)| format!("{:<width$}", sanitize_cell(value)))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn sanitize_cell(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .replace('\t', " ")
        .replace('|', "/")
}

fn cell_len(value: &str) -> usize {
    value.chars().count()
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Warning => "WARN",
        Severity::Critical => "CRIT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_table_report() {
        let mut report = ModuleReport::new(ModuleDescriptor {
            id: 2,
            label: "Disk and Journal Forensics",
            summary: "",
        });
        report.add_warning("Example finding", "Example detail");
        let rendered = render_text_report(&report.finish());
        assert!(rendered.contains("Summary"));
        assert!(rendered.contains("Findings"));
        assert!(rendered.contains("Level | Title"));
        assert!(rendered.contains("WARN"));
    }
}
