use std::io::{self, Write};
use std::sync::OnceLock;

use crate::bypass_scan::types::{Confidence, DetectionStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLang {
    Ru,
    En,
}

static UI_LANG: OnceLock<UiLang> = OnceLock::new();

pub fn init_language_from_prompt() -> UiLang {
    if let Some(lang) = UI_LANG.get().copied() {
        return lang;
    }

    if let Ok(raw) = std::env::var("JLIVE_LANG")
        && let Some(lang) = parse_lang(&raw)
    {
        let _ = UI_LANG.set(lang);
        return lang;
    }

    println!("\nLanguage / Язык");
    println!("1) Русский");
    println!("2) English");
    print!("Select language / Выберите язык: ");
    io::stdout().flush().ok();

    let mut choice = String::new();
    let _ = io::stdin().read_line(&mut choice);
    let lang = match choice.trim() {
        "2" => UiLang::En,
        _ => UiLang::Ru,
    };
    let _ = UI_LANG.set(lang);
    lang
}

pub fn current_lang() -> UiLang {
    if let Some(lang) = UI_LANG.get().copied() {
        return lang;
    }
    if let Ok(raw) = std::env::var("JLIVE_LANG")
        && let Some(lang) = parse_lang(&raw)
    {
        return lang;
    }
    UiLang::Ru
}

pub fn tr<'a>(lang: UiLang, ru: &'a str, en: &'a str) -> &'a str {
    match lang {
        UiLang::Ru => ru,
        UiLang::En => en,
    }
}

pub fn status_label(status: DetectionStatus, lang: UiLang) -> &'static str {
    match (status, lang) {
        (DetectionStatus::Clean, UiLang::Ru) => "чисто",
        (DetectionStatus::Detected, UiLang::Ru) => "обнаружено",
        (DetectionStatus::Warning, UiLang::Ru) => "предупреждение",
        (DetectionStatus::ManualReview, UiLang::Ru) => "ручная проверка",
        (DetectionStatus::Error, UiLang::Ru) => "ошибка",
        (DetectionStatus::Clean, UiLang::En) => "clean",
        (DetectionStatus::Detected, UiLang::En) => "detected",
        (DetectionStatus::Warning, UiLang::En) => "warning",
        (DetectionStatus::ManualReview, UiLang::En) => "manual review",
        (DetectionStatus::Error, UiLang::En) => "error",
    }
}

pub fn confidence_label(confidence: Confidence, lang: UiLang) -> &'static str {
    match (confidence, lang) {
        (Confidence::Low, UiLang::Ru) => "низкая",
        (Confidence::Medium, UiLang::Ru) => "средняя",
        (Confidence::High, UiLang::Ru) => "высокая",
        (Confidence::Low, UiLang::En) => "low",
        (Confidence::Medium, UiLang::En) => "medium",
        (Confidence::High, UiLang::En) => "high",
    }
}

fn parse_lang(raw: &str) -> Option<UiLang> {
    let normalized = raw.trim().to_lowercase();
    match normalized.as_str() {
        "ru" | "rus" | "russian" | "1" => Some(UiLang::Ru),
        "en" | "eng" | "english" | "2" => Some(UiLang::En),
        _ => None,
    }
}

pub fn module_name(lang: UiLang, code: &str, fallback: &str) -> String {
    if lang == UiLang::En {
        return fallback.to_string();
    }

    let localized = match code {
        "bypass01_hosts" => "Подмена hosts-записей",
        "bypass02_restricted_sites" => "Манипуляция Restricted Sites (ZoneMap)",
        "bypass03_disallowrun" => "Блокировка запуска через DisallowRun/RestrictRun",
        "bypass04_fake_signature" => "Поддельная легитимность через подпись",
        "bypass05_service_threads" => "Подвешивание/tamper сервисных потоков",
        "bypass06_timestomp" => "Подмена временных меток (timestomp)",
        "bypass07_app_blockers" => "Блокировщики запуска приложений",
        "bypass08_legacy_console" => "Злоупотребление legacy console",
        "bypass09_prefetch_rename" => "Переименование/маскировка Prefetch",
        "bypass10_stego" => "Скрытие в стеганографии/дописке",
        "bypass11_hidden_cmd_text" => "Скрытый текст CMD (цветовой коллизией)",
        "bypass12_extension_spoof" => "Подмена расширения файла",
        "bypass13_prefetch_attrib" => "Манипуляция атрибутами Prefetch",
        "bypass14_eventlog_clear" => "Очистка журналов событий",
        "bypass15_usn_clear" => "Очистка USN journal",
        "bypass16_file_wiping" => "Стирание файлов (wiping)",
        "bypass17_registry_usb_deletion" => "Удаление USB-следов в реестре",
        "bypass18_prefetch_amcache_wipe" => "Очистка Prefetch/Amcache",
        "bypass19_browser_cache_wipe" => "Очистка кэша/истории браузеров",
        "bypass20_shadowcopy_delete" => "Удаление теневых копий/точек восстановления",
        "bypass21_pagefile_hiber_wipe" => "Антифорензика pagefile/hiberfil",
        "bypass22_thumbnail_cache_delete" => "Удаление кэша миниатюр",
        "bypass24_covert_channels" => "Скрытые каналы (VPN/Tor/туннели)",
        "bypass25_ram_disk" => "RAM-диск для обхода следов",
        "bypass26_log_flooding" => "Зашумление журналов событий",
        "bypass27_usb_policy_disable" => "Отключение USB-политиками",
        "bypass28_wef_tamper" => "Тамперинг WEF/пересылки событий",
        "bypass29_restore_point_removal" => "Удаление точек восстановления",
        "bypass30_trim_tamper" => "Тамперинг TRIM/DeleteNotify",
        "bypass31_polyglot_append" => "Полиглот/дописка после EOF",
        "bypass32_fileless_amsi_lolbins" => "Fileless/AMSI bypass/LOLBins",
        "bypass33_container_prune" => "Очистка следов контейнеров",
        "bypass34_cloud_sync_delete" => "Удаление в облачных синхронизаторах",
        "bypass35_exif_timestamp_edit" => "Правка EXIF-времени",
        "bypass37_fake_usb_artifacts" => "Поддельные USB-артефакты",
        "bypass38_mac_randomization" => "Рандомизация/подмена MAC",
        "bypass39_dns_fuzzing" => "DNS-фаззинг/туннелирование",
        "bypass40_secure_boot_tamper" => "Тамперинг Secure Boot/BCD",
        _ => fallback,
    };

    localized.to_string()
}

pub fn localize_runtime_text(lang: UiLang, text: &str) -> String {
    if lang == UiLang::En {
        return text.to_string();
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Some(v) = exact_ru_text(trimmed) {
        return v.to_string();
    }

    if let Some(v) = translate_counted_phrase(trimmed) {
        return v;
    }

    trimmed.to_string()
}

fn exact_ru_text(text: &str) -> Option<&'static str> {
    match text {
        "No suspicious hosts overrides detected." => {
            Some("Подозрительных переопределений в hosts не обнаружено.")
        }
        "No suspicious restricted-site mappings detected." => {
            Some("Подозрительных записей Restricted Sites не обнаружено.")
        }
        "No suspicious application blocking policy detected." => {
            Some("Подозрительных политик блокировки запуска не обнаружено.")
        }
        "No high-confidence signature tampering found." => {
            Some("Высокодостоверных признаков подделки/порчи подписи не обнаружено.")
        }
        "No clear service health anomalies for targeted services." => {
            Some("Явных аномалий состояния целевых сервисов не обнаружено.")
        }
        "Hosts contains active non-comment entries (policy: any active entry is bypass indicator)." => {
            Some(
                "В hosts есть активные (не закомментированные) строки. По политике это считается индикатором bypass.",
            )
        }
        "Legacy console mode is not enabled in inspected registry keys." => {
            Some("Legacy Console mode в проверенных ключах реестра не включён.")
        }
        "Prefetch folder name looks normal." => Some("Имя папки Prefetch выглядит штатно."),
        "No high-confidence stego/polyglot evidence found." => {
            Some("Высокодостоверных признаков стеганографии/полиглота не обнаружено.")
        }
        "No console profiles with equal foreground/background color found." => {
            Some("Профили консоли с одинаковым цветом текста и фона не обнаружены.")
        }
        "No high-confidence extension spoofing indicators found." => {
            Some("Высокодостоверных индикаторов spoofing расширения не обнаружено.")
        }
        "No high-confidence timestomp command traces found in available telemetry." => {
            Some("Высокодостоверных следов timestomp-команд в доступной телеметрии не обнаружено.")
        }
        "No high-confidence USN journal clear evidence found." => {
            Some("Высокодостоверных признаков очистки USN journal не обнаружено.")
        }
        "No strong wiping-tool evidence found." => {
            Some("Сильных подтверждений запуска инструментов file wiping не найдено.")
        }
        "No high-confidence USBSTOR deletion events found." => {
            Some("Высокодостоверных событий удаления USBSTOR не обнаружено.")
        }
        "No strong evidence of Prefetch/Amcache mass deletion." => {
            Some("Сильных подтверждений массовой очистки Prefetch/Amcache не обнаружено.")
        }
        "No high-confidence shadow-copy deletion evidence found." => {
            Some("Высокодостоверных признаков удаления теневых копий не обнаружено.")
        }
        "No high-confidence browser wipe evidence found. Missing browser files alone are treated as non-actionable." => {
            Some(
                "Высокодостоверных признаков очистки браузерных артефактов не найдено. Само по себе отсутствие файлов браузера не считается инцидентом.",
            )
        }
        "No direct anti-forensic pagefile/hibernation command traces found." => {
            Some("Прямых антифорензик-команд по pagefile/hibernation не обнаружено.")
        }
        "No high-confidence thumbnail-cache wipe evidence found." => {
            Some("Высокодостоверных признаков очистки thumbnail-cache не обнаружено.")
        }
        "Detected event-log channel anomalies without direct clear commands. This may be policy hardening or tampering and requires baseline validation." => {
            Some(
                "Обнаружены аномалии каналов журналов без прямых команд очистки. Это может быть легитимным hardening или tamper; нужна сверка с baseline.",
            )
        }
        "Found timestamp-changing command(s), but no matching Sysmon EventID 2 in the current retention window." => {
            Some(
                "Найдены команды изменения временных меток, но в текущем окне ретенции нет соответствующих Sysmon EventID 2.",
            )
        }
        "No suspicious hidden/read-only/system attributes found on Prefetch .pf files." => Some(
            "Подозрительных атрибутов hidden/read-only/system на файлах Prefetch (.pf) не обнаружено.",
        ),
        "Single application-blocker indicator detected (IFEO/config/telemetry)." => {
            Some("Обнаружен одиночный индикатор блокировки приложений (IFEO/config/telemetry).")
        }
        "Shadow-copy tooling traces found while no shadow copies are currently present." => Some(
            "Есть следы использования shadow-copy инструментов, при этом теневых копий сейчас нет.",
        ),
        "ADS activity found in telemetry, but scan-root stream content is currently not recoverable." => {
            Some(
                "В телеметрии найдены признаки ADS-активности, но содержимое потоков в корнях сканирования сейчас не извлекается.",
            )
        }
        "Single covert-channel indicator detected (active-state policy)." => {
            Some("Обнаружен одиночный индикатор covert-channel (по политике active-state).")
        }
        "No high-confidence RAM disk bypass pattern found." => {
            Some("Высокодостоверного паттерна bypass через RAM disk не обнаружено.")
        }
        "No high-confidence event-flooding pattern found." => {
            Some("Высокодостоверного паттерна зашумления журналов не обнаружено.")
        }
        "No high-confidence USB policy tampering evidence found." => {
            Some("Высокодостоверных признаков tamper USB-политик не обнаружено.")
        }
        "No high-confidence event-forwarding tamper evidence found." => {
            Some("Высокодостоверных признаков tamper пересылки событий не обнаружено.")
        }
        "No high-confidence restore-point deletion evidence found." => {
            Some("Высокодостоверных признаков удаления точек восстановления не обнаружено.")
        }
        "No high-confidence TRIM tamper evidence found." => {
            Some("Высокодостоверных признаков tamper TRIM не обнаружено.")
        }
        "No high-confidence appended payload after file EOF marker found." => {
            Some("Высокодостоверных признаков дописки payload после EOF не обнаружено.")
        }
        "Single LOLBin/fileless indicator detected in telemetry." => {
            Some("Обнаружен одиночный индикатор LOLBin/fileless в телеметрии.")
        }
        "Container tooling execution traces exist with empty runtime inventory (possible cleanup)." => {
            Some(
                "Есть следы запуска container-инструментов при пустом runtime inventory (возможна очистка).",
            )
        }
        "No high-confidence cloud sync delete/purge command evidence found." => {
            Some("Высокодостоверных признаков cloud delete/purge команд не обнаружено.")
        }
        "No explicit EXIF timestamp-manipulation command evidence found." => {
            Some("Явных команд изменения EXIF-времени не обнаружено.")
        }
        "Single USB-HID injection indicator detected; monitor for command-execution follow-up." => {
            Some(
                "Обнаружен одиночный индикатор USB-HID инъекции; нужен контроль последующего выполнения команд.",
            )
        }
        "No strong SetupAPI/registry/device inconsistency found." => {
            Some("Сильных несоответствий SetupAPI/реестра/устройств не обнаружено.")
        }
        "No strong MAC-randomization tamper command evidence found." => {
            Some("Сильных подтверждений tamper-команд MAC-randomization не обнаружено.")
        }
        "No high-confidence DNS tunneling tool evidence found." => {
            Some("Высокодостоверных признаков DNS tunneling tool не обнаружено.")
        }
        "No high-confidence BCD tamper command evidence found." => {
            Some("Высокодостоверных признаков BCD tamper-команд не обнаружено.")
        }
        "Inventory parsed successfully." => Some("Инвентарь теневых копий успешно разобран."),
        "USN journal context" => Some("Контекст USN journal"),
        "NTFS metadata context" => Some("Контекст NTFS-метаданных"),
        "Process/Script command telemetry" => {
            Some("Телеметрия процессов/скриптов (командные следы)")
        }
        "Process/Script telemetry" => Some("Телеметрия процессов/скриптов"),
        "LOLBin execution telemetry" => Some("Телеметрия выполнения LOLBin"),
        "ADS scan scope" => Some("Область сканирования ADS"),
        "Container runtime inventory" => Some("Инвентарь контейнерной среды"),
        "Event log channel metadata" => Some("Метаданные каналов журналов"),
        "Shadow-copy inventory" => Some("Инвентарь теневых копий"),
        "Browser history artifact state" => Some("Состояние артефактов истории браузеров"),
        "Interpretation note" => Some("Пояснение интерпретации"),
        "IFEO Debugger" => Some("IFEO Debugger"),
        "Recommendations:" => Some("Рекомендации:"),
        "Remove unauthorized IFEO/AppLocker/SRP rules and export policy for audit." => Some(
            "Удалите несанкционированные IFEO/AppLocker/SRP правила и выгрузите политику для аудита.",
        ),
        "Correlate event timestamps with process execution (wevtutil/Clear-EventLog) and preserve centralized copies (WEF/SIEM)." => {
            Some(
                "Сопоставьте таймстемпы событий с выполнением процессов (wevtutil/Clear-EventLog) и сохраните централизованные копии (WEF/SIEM).",
            )
        }
        "Validate if maintenance tooling could explain command traces before final attribution." => {
            Some(
                "Проверьте, может ли легитимное обслуживание объяснить командные следы до финальной атрибуции.",
            )
        }
        "Correlate command traces with adjacent ransomware/cleanup activity and preserve remote logs." => {
            Some(
                "Сопоставьте командные следы с соседней ransomware/cleanup активностью и сохраните удалённые логи.",
            )
        }
        "Validate whether backup/maintenance tooling could legitimately delete shadow copies." => {
            Some("Проверьте, мог ли backup/maintenance софт легитимно удалить теневые копии.")
        }
        "Correlate with approved VPN inventory and perimeter DNS/proxy/firewall telemetry." => {
            Some(
                "Сопоставьте с утверждённым VPN-инвентарём и периметровой DNS/proxy/firewall телеметрией.",
            )
        }
        _ => None,
    }
}

fn translate_counted_phrase(text: &str) -> Option<String> {
    let mut parts = text.splitn(2, ' ');
    let count = parts.next()?.parse::<usize>().ok()?;
    let tail = parts.next()?.trim();

    let mapped = match tail {
        "IFEO debugger entries" => format!("{count} записей IFEO Debugger"),
        "suspicious channel state(s)" => format!("{count} подозрительных состояний канала"),
        "ADS command trace(s)" => format!("{count} следов ADS-команд"),
        "clear command trace(s)" => format!("{count} следов команд очистки"),
        "related tool prefetch file(s)" => {
            format!("{count} prefetch-файлов связанных инструментов")
        }
        "connected adapter indicator(s)" => format!("{count} индикаторов подключённых адаптеров"),
        "suspicious command execution hit(s)" => {
            format!("{count} подозрительных срабатываний выполнения команд")
        }
        t if t.starts_with("suspicious LOLBin event(s) across ") && t.ends_with(" class(es)") => {
            let classes = t
                .trim_start_matches("suspicious LOLBin event(s) across ")
                .trim_end_matches(" class(es)");
            format!("{count} подозрительных LOLBin-событий в {classes} класс(ах)")
        }
        t if t.starts_with("volume(s) checked") => format!("{count} том(ов) проверено"),
        _ => return None,
    };

    Some(mapped)
}
