use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use colored::Colorize;
use colored::control::{set_override, set_virtual_terminal};

mod activity;
mod context;
mod detectors;
mod engine;
mod i18n;
mod keywords;
mod logger;
mod report;
mod types;
pub(crate) mod utils;

use context::{ScanContext, ScanProfile};
use i18n::{
    UiLang, confidence_label, init_language_from_prompt, localize_runtime_text, module_name,
    status_label, tr,
};
use types::{DetectionStatus, ScanReport};

pub fn run_bypass_scan_flow() -> Result<()> {
    init_colors();
    let lang = init_language_from_prompt();

    println!("\n{}", tr(lang, "Сканер байпасов", "Bypass Scanner").bold());
    println!(
        "1) {}",
        tr(
            lang,
            "Быстрый профиль (1-2 мин)",
            "Quick profile (target 1-2 min)"
        )
    );
    println!("2) {}", tr(lang, "Глубокий профиль", "Deep profile"));
    println!("3) {}", tr(lang, "Назад", "Back"));
    print!("{} ", tr(lang, "Выберите профиль:", "Select profile:"));
    io::stdout().flush().ok();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    if choice.trim() == "3" {
        return Ok(());
    }

    let Some(profile) = ScanProfile::from_menu_choice(&choice) else {
        println!("{}", tr(lang, "Неизвестный профиль.", "Unknown profile."));
        return Ok(());
    };

    print!(
        "{}",
        tr(
            lang,
            "Необязательный путь сканирования (Enter = авто",
            "Optional custom scan path (Enter = auto"
        )
    );
    if profile == ScanProfile::Deep {
        print!(
            "{}",
            tr(lang, ": все фиксированные диски", ": all fixed drives")
        );
    } else {
        print!(
            "{}",
            tr(lang, ": пользовательские hotspot-пути", ": user hotspots")
        );
    }
    print!("): ");
    io::stdout().flush().ok();
    let mut custom = String::new();
    io::stdin().read_line(&mut custom)?;
    let custom_root = parse_optional_path(custom.trim(), lang);

    let ctx = ScanContext::new(profile, custom_root);
    let logger = logger::JsonLogger::new(&ctx.report_dir)?;
    logger.log(
        "flow",
        "info",
        "scan context created",
        serde_json::json!({
            "profile": profile.as_str(),
            "roots": ctx.scan_roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "activity_seed_count": ctx.activity_paths.len(),
        }),
    );

    println!(
        "{}",
        tr(
            lang,
            "Запуск оптимизированного сканирования...",
            "Starting optimized bypass scan..."
        )
        .cyan()
    );
    println!(
        "{} {}",
        tr(lang, "Профиль:", "Profile:").white().bold(),
        profile.as_str()
    );
    println!(
        "{} {}",
        tr(lang, "Корни сканирования:", "Roots:").white().bold(),
        ctx.scan_roots.len()
    );
    if profile == ScanProfile::Quick {
        println!(
            "{} {}",
            tr(lang, "Сиды недавней активности:", "Recent activity seeds:")
                .white()
                .bold(),
            ctx.activity_paths.len()
        );
    }

    let scan_report = engine::run_scan(&ctx, &logger);
    let (json_path, text_path) = report::save_report(&scan_report, &ctx.report_dir, lang)?;

    print_cli_summary(&scan_report, lang);

    println!(
        "\n{}",
        tr(lang, "Сохранённые отчёты:", "Saved reports:")
            .white()
            .bold()
    );
    println!("- JSON: {}", json_path.display().to_string().cyan());
    println!("- TXT : {}", text_path.display().to_string().cyan());
    println!("- LOG : {}", logger.path().display().to_string().cyan());

    Ok(())
}

fn parse_optional_path(raw: &str, lang: UiLang) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(raw);
    if candidate.exists() {
        Some(candidate)
    } else {
        println!(
            "{}",
            tr(
                lang,
                "Путь не найден, использую автоматические корни.",
                "Path not found, using automatic roots."
            )
            .yellow()
        );
        None
    }
}

fn print_cli_summary(report: &ScanReport, lang: UiLang) {
    println!(
        "\n{} {} {}",
        tr(lang, "Сканирование завершено за", "Scan finished in")
            .white()
            .bold(),
        report.duration_ms.to_string().bold(),
        "ms".bold()
    );

    println!(
        "{} {} | {} {} | {} {}",
        tr(lang, "Обнаружено:", "Detected:").white().bold(),
        report.detected_count.to_string().red().bold(),
        tr(lang, "Предупреждения:", "Warnings:").white().bold(),
        report.warning_count.to_string().yellow().bold(),
        tr(lang, "Ручная проверка:", "Manual review:")
            .white()
            .bold(),
        report.manual_review_count.to_string().magenta().bold()
    );

    if report.detected_count == 0 {
        println!("{}", tr(lang, "Чисто", "Clean").green().bold());
    } else {
        let names = report
            .results
            .iter()
            .filter(|r| r.status == DetectionStatus::Detected)
            .map(|r| format!("{} ({})", module_name(lang, &r.code, &r.name), r.code))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{} {}",
            tr(lang, "Найдены байпасы:", "Bypasses found:").red().bold(),
            names.red()
        );
    }

    println!(
        "\n{}",
        tr(lang, "Статусы модулей:", "Module statuses:")
            .white()
            .bold()
    );
    print_status_blocks(report, lang);

    let findings = report
        .results
        .iter()
        .filter(|r| r.status != DetectionStatus::Clean)
        .collect::<Vec<_>>();

    if findings.is_empty() {
        return;
    }

    println!(
        "\n{}",
        tr(
            lang,
            "Детали по не-clean модулям:",
            "Details for non-clean modules:"
        )
        .white()
        .bold()
    );

    for result in findings {
        println!(
            "\n[{}] {}",
            result.code.cyan().bold(),
            module_name(lang, &result.code, &result.name).bold(),
        );
        println!(
            "{} {} | {} {} | {} {}",
            tr(lang, "Статус:", "Status:").white().bold(),
            colorize_status(status_label(result.status, lang), result.status),
            tr(lang, "Уверенность:", "Confidence:").white().bold(),
            confidence_label(result.confidence, lang),
            tr(lang, "Длительность:", "Duration:").white().bold(),
            format!("{} ms", result.duration_ms)
        );
        println!(
            "{} {}",
            tr(lang, "Сводка:", "Summary:").white().bold(),
            localize_runtime_text(lang, &result.summary)
        );

        for item in &result.evidence {
            println!(
                "{} {} | {}",
                "-".white().bold(),
                localize_runtime_text(lang, &item.source).white().bold(),
                localize_runtime_text(lang, &item.summary)
            );
            print_wrapped_detail_lines(&item.details, 160);
        }

        if !result.recommendations.is_empty() {
            println!(
                "{}",
                tr(lang, "Рекомендации:", "Recommendations:").white().bold()
            );
            for rec in &result.recommendations {
                println!("  * {}", localize_runtime_text(lang, rec));
            }
        }
    }
}

fn print_wrapped_detail_lines(details: &str, width: usize) {
    let cleaned = details.replace('\r', "").trim().to_string();
    if cleaned.is_empty() {
        return;
    }

    let mut items = cleaned
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    if items.len() > 20 {
        items.truncate(20);
    }

    for item in items {
        for (index, line) in wrap_text(item, width).into_iter().enumerate() {
            if index == 0 {
                println!("  - {}", line);
            } else {
                println!("    {}", line);
            }
        }
    }
}

fn print_status_blocks(report: &ScanReport, lang: UiLang) {
    for result in &report.results {
        println!(
            "[{}] {}",
            result.code.cyan().bold(),
            module_name(lang, &result.code, &result.name).bold()
        );
        println!(
            "  {} {} | {} {} | {} {}",
            tr(lang, "Статус:", "Status:").white().bold(),
            colorize_status(status_label(result.status, lang), result.status),
            tr(lang, "Уверенность:", "Confidence:").white().bold(),
            confidence_label(result.confidence, lang),
            tr(lang, "Длительность:", "Duration:").white().bold(),
            format!("{} ms", result.duration_ms)
        );
        println!("  {}", tr(lang, "Сводка:", "Summary:").white().bold());
        for line in wrap_text(&localize_runtime_text(lang, &result.summary), 132) {
            println!("    {}", line);
        }
        println!("{}", "─".repeat(92).bright_black());
    }
}

fn wrap_text(input: &str, width: usize) -> Vec<String> {
    let cleaned = input.replace('\r', "");
    let mut out = Vec::new();

    for raw_line in cleaned.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let mut current = String::new();
        for word in line.split_whitespace() {
            for chunk in split_long_token(word, width) {
                let pending = if current.is_empty() {
                    chunk.chars().count()
                } else {
                    current.chars().count() + 1 + chunk.chars().count()
                };

                if pending > width && !current.is_empty() {
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

fn init_colors() {
    #[cfg(windows)]
    {
        if !set_virtual_terminal(true).is_ok() {
            set_override(false);
        }
    }
}

fn colorize_status(label: &str, status: DetectionStatus) -> colored::ColoredString {
    match status {
        DetectionStatus::Clean => label.green().bold(),
        DetectionStatus::Detected => label.red().bold(),
        DetectionStatus::Warning => label.yellow().bold(),
        DetectionStatus::ManualReview => label.magenta().bold(),
        DetectionStatus::Error => label.bright_red().bold(),
    }
}
