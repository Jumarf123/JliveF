use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::bypass_scan::i18n::{
    UiLang, confidence_label, localize_runtime_text, module_name, status_label, tr,
};
use crate::bypass_scan::types::{DetectionStatus, ScanReport};

const MAX_EVIDENCE_LINES_PER_ITEM: usize = 18;
const WRAP_WIDTH: usize = 116;
const SECTION_RULE: &str =
    "------------------------------------------------------------------------";

pub fn save_report(
    report: &ScanReport,
    report_dir: &Path,
    lang: UiLang,
) -> Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(report_dir)?;
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let json_path = report_dir.join(format!("bypass_scan_result_{ts}.json"));
    let text_path = report_dir.join(format!("bypass_scan_result_{ts}.txt"));

    fs::write(&json_path, serde_json::to_string_pretty(report)?)?;
    fs::write(&text_path, render_text_report(report, lang))?;

    Ok((json_path, text_path))
}

fn render_text_report(report: &ScanReport, lang: UiLang) -> String {
    let mut out = String::new();
    out.push_str(tr(lang, "Отчёт сканера байпасов\n", "Bypass scan report\n"));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Начало:", "Started:"),
        report.started_at
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Завершение:", "Finished:"),
        report.finished_at
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Длительность (мс):", "Duration(ms):"),
        report.duration_ms
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Хост:", "Host:"),
        report.host_name
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Профиль:", "Profile:"),
        report.profile
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Модулей:", "Modules:"),
        report.detector_count
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Сиды активности:", "Activity seeds:"),
        report.activity_seed_count
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Итог:", "Overall:"),
        report.overall_status
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Обнаружено:", "Detected:"),
        report.detected_count
    ));
    out.push_str(&format!(
        "{} {}\n",
        tr(lang, "Предупреждения:", "Warnings:"),
        report.warning_count
    ));
    out.push_str(&format!(
        "{} {}\n\n",
        tr(lang, "Ручная проверка:", "Manual review:"),
        report.manual_review_count
    ));

    for (index, result) in report.results.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }

        out.push_str(&format!(
            "[{code}] {name}\n",
            code = result.code,
            name = module_name(lang, &result.code, &result.name),
        ));
        out.push_str(&format!(
            "{} {}\n",
            tr(lang, "Статус:", "Status:"),
            status_label(result.status, lang)
        ));
        out.push_str(&format!(
            "{} {}\n",
            tr(lang, "Уверенность:", "Confidence:"),
            confidence_label(result.confidence, lang)
        ));
        out.push_str(&format!(
            "{} {}\n",
            tr(lang, "Длительность (мс):", "Duration(ms):"),
            result.duration_ms
        ));
        out.push_str(tr(lang, "Сводка:\n", "Summary:\n"));
        append_wrapped_block(
            &mut out,
            &localize_runtime_text(lang, &result.summary),
            2,
            WRAP_WIDTH,
        );

        if let Some(error) = &result.error {
            out.push_str(tr(lang, "Ошибка:\n", "Error:\n"));
            append_wrapped_block(&mut out, error, 2, WRAP_WIDTH);
        }

        if !result.evidence.is_empty() {
            out.push_str(tr(lang, "Свидетельства:\n", "Evidence:\n"));
            for (item_index, item) in result.evidence.iter().enumerate() {
                out.push_str(&format!(
                    "  {}. {}\n",
                    item_index + 1,
                    localize_runtime_text(lang, &item.source)
                ));
                out.push_str(&format!("     {}\n", tr(lang, "Сводка:", "Summary:")));
                append_wrapped_block(
                    &mut out,
                    &localize_runtime_text(lang, &item.summary),
                    7,
                    WRAP_WIDTH,
                );
                if !item.details.trim().is_empty() {
                    out.push_str(&format!("     {}\n", tr(lang, "Детали:", "Details:")));
                    out.push_str(&render_evidence_details(&item.details, 7));
                }
            }
        }

        if !result.recommendations.is_empty() {
            out.push_str(tr(lang, "Рекомендации:\n", "Recommendations:\n"));
            for rec in &result.recommendations {
                append_wrapped_bullet(&mut out, &localize_runtime_text(lang, rec), 2, WRAP_WIDTH);
            }
        }

        out.push_str(SECTION_RULE);
        out.push('\n');
    }

    if report.detected_count == 0 {
        out.push_str(&format!(
            "{} {}\n",
            tr(lang, "Результат:", "Result:"),
            tr(lang, "Чисто", "Clean")
        ));
    } else {
        let names = report
            .results
            .iter()
            .filter(|r| r.status == DetectionStatus::Detected)
            .map(|r| format!("{} ({})", module_name(lang, &r.code, &r.name), r.code))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "{} {} {names}\n",
            tr(lang, "Результат:", "Result:"),
            tr(lang, "найдены байпасы -", "bypasses found -")
        ));
    }

    out
}

fn render_evidence_details(details: &str, indent: usize) -> String {
    let cleaned = details.replace('\r', "").trim().to_string();
    if cleaned.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut items = cleaned
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if items.len() <= 1 {
        append_wrapped_block(&mut out, &cleaned, indent, WRAP_WIDTH);
        return out;
    }

    let omitted = items.len().saturating_sub(MAX_EVIDENCE_LINES_PER_ITEM);
    if items.len() > MAX_EVIDENCE_LINES_PER_ITEM {
        items.truncate(MAX_EVIDENCE_LINES_PER_ITEM);
    }

    for item in items {
        append_wrapped_bullet(&mut out, item, indent, WRAP_WIDTH);
    }

    if omitted > 0 {
        out.push_str(&format!("{}... +{} more\n", " ".repeat(indent), omitted));
    }

    out
}

fn append_wrapped_block(out: &mut String, text: &str, indent: usize, width: usize) {
    for line in wrap_text(text, width) {
        out.push_str(&" ".repeat(indent));
        out.push_str(&line);
        out.push('\n');
    }
}

fn append_wrapped_bullet(out: &mut String, text: &str, indent: usize, width: usize) {
    for (index, line) in wrap_text(text, width).into_iter().enumerate() {
        out.push_str(&" ".repeat(indent));
        if index == 0 {
            out.push_str("- ");
        } else {
            out.push_str("  ");
        }
        out.push_str(&line);
        out.push('\n');
    }
}

fn wrap_text(input: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for raw_line in input.replace('\r', "").lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let mut current = String::new();
        for word in line.split_whitespace() {
            for chunk in split_long_token(word, width) {
                let pending_len = if current.is_empty() {
                    chunk.chars().count()
                } else {
                    current.chars().count() + 1 + chunk.chars().count()
                };

                if pending_len > width && !current.is_empty() {
                    out.push(current);
                    current = chunk;
                } else {
                    if !current.is_empty() {
                        current.push(' ');
                    }
                    current.push_str(&chunk);
                }
            }
        }

        if !current.is_empty() {
            out.push(current);
        }
    }

    if out.is_empty() && !input.trim().is_empty() {
        return split_long_token(input.trim(), width);
    }

    out
}

fn split_long_token(token: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![token.to_string()];
    }
    if token.chars().count() <= width {
        return vec![token.to_string()];
    }

    let mut out = Vec::new();
    let mut chunk = String::new();
    for ch in token.chars() {
        chunk.push(ch);
        if chunk.chars().count() >= width {
            out.push(std::mem::take(&mut chunk));
        }
    }

    if !chunk.is_empty() {
        out.push(chunk);
    }

    out
}
