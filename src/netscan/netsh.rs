use crate::netscan::report::{Finding, Report};
use encoding_rs::Encoding;
use std::collections::HashMap;
use std::process::Command;

const NETSH_PATH: &str = "netsh int tcp show global";

fn decode_output(bytes: &[u8]) -> String {
    if let Ok(s) = String::from_utf8(bytes.to_vec()) {
        return s;
    }

    for label in ["ibm866", "windows-1251"] {
        if let Some(enc) = Encoding::for_label(label.as_bytes()) {
            let (cow, _, _) = enc.decode(bytes);
            return cow.into_owned();
        }
    }

    String::from_utf8_lossy(bytes).into_owned()
}

pub fn run_netsh_global() -> Result<String, String> {
    let output = Command::new("netsh")
        .args(["int", "tcp", "show", "global"])
        .output()
        .map_err(|e| format!("Не удалось запустить netsh: {}", e))?;

    if !output.status.success() {
        let stderr = decode_output(&output.stderr);
        return Err(format!(
            "netsh завершился с ошибкой (код {}): {}",
            output.status,
            stderr.trim()
        ));
    }

    Ok(decode_output(&output.stdout))
}

struct NetshRule {
    name: &'static str,
    keywords: &'static [&'static str],
    validator: fn(&str) -> Option<String>,
}

fn extract_value(line: &str) -> String {
    if let Some(idx) = line.find(':') {
        return line[idx + 1..].trim().to_string();
    }
    line.split_whitespace().last().unwrap_or("").to_string()
}

fn rules() -> Vec<NetshRule> {
    vec![
        NetshRule {
            name: "Receive-Side Scaling State",
            keywords: &[
                "receive-side scaling state",
                "состояние масштабирования на стороне приема",
            ],
            validator: |value| {
                if !value.to_lowercase().contains("enabled") {
                    Some("Параметр должен быть enabled".to_string())
                } else {
                    None
                }
            },
        },
        NetshRule {
            name: "Receive Segment Coalescing State",
            keywords: &[
                "receive segment coalescing state",
                "состояние объединения сегментов приема",
            ],
            validator: |value| {
                if !value.to_lowercase().contains("enabled") {
                    Some("Параметр должен быть enabled".to_string())
                } else {
                    None
                }
            },
        },
        NetshRule {
            name: "ECN Capability",
            keywords: &["ecn capability", "мощность ecn"],
            validator: |value| {
                if value.to_lowercase().contains("enabled") {
                    Some("ECN должен быть disabled".to_string())
                } else {
                    None
                }
            },
        },
        NetshRule {
            name: "Congestion Control Provider",
            keywords: &[
                "congestion control provider",
                "поставщик дополнительного компонента контроля перегрузки",
            ],
            validator: |value| {
                let val = value.trim().to_lowercase();
                match val.as_str() {
                    "default" | "cubic" | "ctcp" => None,
                    _ => Some("Недопустимый провайдер управления перегрузкой".to_string()),
                }
            },
        },
    ]
}

pub fn parse_netsh_output(output: &str, report: &mut Report) {
    let rules = rules();
    let mut seen: HashMap<&str, String> = HashMap::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_lowercase();

        for rule in &rules {
            if rule
                .keywords
                .iter()
                .any(|kw| lower.contains(&kw.to_lowercase()))
            {
                let value = extract_value(trimmed);
                seen.entry(rule.name).or_insert_with(|| value.clone());
                break;
            }
        }
    }

    for rule in &rules {
        report.inc_checked();
        if let Some(value) = seen.get(rule.name) {
            if let Some(msg) = (rule.validator)(value) {
                report.add_violation(Finding::new(
                    rule.name,
                    NETSH_PATH,
                    rule.name,
                    Some(value.clone()),
                    msg,
                ));
            }
        } else {
            report.add_warning(Finding::new(
                rule.name,
                NETSH_PATH,
                rule.name,
                None,
                "Параметр не найден в выводе netsh",
            ));
        }
    }
}

pub fn scan_netsh(report: &mut Report) {
    match run_netsh_global() {
        Ok(output) => parse_netsh_output(&output, report),
        Err(err) => report.add_warning(Finding::new(
            "netsh",
            NETSH_PATH,
            String::new(),
            None,
            format!("Не удалось выполнить команду: {}", err),
        )),
    }
}
