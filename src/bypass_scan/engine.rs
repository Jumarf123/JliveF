use std::time::Instant;
use std::{
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
};

use rayon::prelude::*;

use crate::bypass_scan::context::ScanContext;
use crate::bypass_scan::detectors;
use crate::bypass_scan::i18n::{UiLang, current_lang};
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, DetectionStatus, ScanReport};
use crate::bypass_scan::utils::{prewarm_runtime_caches, reset_runtime_caches};

#[derive(Clone, Copy)]
struct DetectorMeta {
    code: &'static str,
    id: u8,
    run: fn(&ScanContext, &JsonLogger) -> BypassResult,
}

pub fn run_scan(ctx: &ScanContext, logger: &JsonLogger) -> ScanReport {
    let started = Instant::now();
    logger.info("engine", "starting bypass scan");

    reset_runtime_caches();
    let prewarm_started = Instant::now();
    let prewarm_stats = prewarm_runtime_caches(ctx);
    logger.log(
        "engine",
        "info",
        "runtime caches prewarmed",
        serde_json::json!({
            "duration_ms": prewarm_started.elapsed().as_millis(),
            "event_channels_warmed": prewarm_stats.event_channels_warmed,
            "candidate_exts_indexed": prewarm_stats.candidate_exts_indexed,
            "candidate_files_indexed": prewarm_stats.candidate_files_indexed,
        }),
    );

    let detectors = detector_registry();
    let total_detectors = detectors.len().max(1);
    let completed = AtomicUsize::new(0);
    render_progress(0, total_detectors, started.elapsed().as_secs());

    let mut results: Vec<BypassResult> = detectors
        .into_par_iter()
        .map(|detector| {
            let result = execute_detector(detector, ctx, logger);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            render_progress(done, total_detectors, started.elapsed().as_secs());
            result
        })
        .collect();

    results.sort_by_key(|r| r.id);

    let detected_count = results
        .iter()
        .filter(|r| r.status == DetectionStatus::Detected)
        .count();
    let warning_count = results
        .iter()
        .filter(|r| r.status == DetectionStatus::Warning)
        .count();
    let manual_review_count = results
        .iter()
        .filter(|r| r.status == DetectionStatus::ManualReview)
        .count();

    let overall_status = if detected_count > 0 {
        "detected"
    } else if warning_count > 0 || manual_review_count > 0 {
        "warning"
    } else {
        "clean"
    }
    .to_string();

    let report = ScanReport {
        started_at: ctx.started_at_utc.clone(),
        finished_at: chrono::Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis(),
        profile: ctx.profile.as_str().to_string(),
        activity_seed_count: ctx.activity_paths.len(),
        host_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string()),
        detector_count: results.len(),
        detected_count,
        warning_count,
        manual_review_count,
        overall_status,
        results,
    };

    logger.log(
        "engine",
        "info",
        "scan finished",
        serde_json::json!({
            "duration_ms": report.duration_ms,
            "detected_count": report.detected_count,
            "warning_count": report.warning_count,
            "manual_review_count": report.manual_review_count,
        }),
    );

    report
}

fn execute_detector(
    detector: DetectorMeta,
    ctx: &ScanContext,
    logger: &JsonLogger,
) -> BypassResult {
    let item_start = Instant::now();
    logger.log(
        detector.code,
        "info",
        "detector started",
        serde_json::json!({"id": detector.id}),
    );

    let mut result = (detector.run)(ctx, logger);
    normalize_single_indicator_status(&mut result);
    result.duration_ms = item_start.elapsed().as_millis();

    logger.log(
        detector.code,
        "info",
        "detector finished",
        serde_json::json!({
            "status": result.status.as_label(),
            "duration_ms": result.duration_ms,
            "evidence_count": result.evidence.len(),
        }),
    );

    result
}

fn render_progress(done: usize, total: usize, elapsed_secs: u64) {
    let total = total.max(1);
    let done = done.min(total);
    let percent = (done * 100) / total;
    let bar_width = 28usize;
    let filled = (bar_width * percent) / 100;
    let bar = format!(
        "{}{}",
        "#".repeat(filled),
        "-".repeat(bar_width.saturating_sub(filled))
    );

    let progress_label = match current_lang() {
        UiLang::Ru => "Прогресс",
        UiLang::En => "Progress",
    };

    print!(
        "\r{}: [{}] {:>3}% ({}/{})  {}s",
        progress_label, bar, percent, done, total, elapsed_secs
    );
    let _ = std::io::stdout().flush();
    if done >= total {
        println!();
    }
}

fn normalize_single_indicator_status(result: &mut BypassResult) {
    if !strict_single_indicator_mode_enabled() {
        return;
    }

    match result.status {
        DetectionStatus::Warning | DetectionStatus::ManualReview => {
            result.status = DetectionStatus::Detected;
            if !result
                .summary
                .to_lowercase()
                .contains("single-indicator mode")
            {
                result.summary = format!("{} [single-indicator mode]", result.summary);
            }
        }
        _ => {}
    }
}

fn strict_single_indicator_mode_enabled() -> bool {
    strict_flag_from_value(std::env::var("JLIVE_STRICT_SINGLE_INDICATOR_BYPASS").ok())
}

fn strict_flag_from_value(value: Option<String>) -> bool {
    value
        .map(|v| {
            let normalized = v.trim().to_lowercase();
            !(normalized == "0"
                || normalized == "false"
                || normalized == "off"
                || normalized == "no")
        })
        .unwrap_or(true)
}

fn detector_registry() -> Vec<DetectorMeta> {
    vec![
        DetectorMeta {
            code: "bypass01_hosts",
            id: 1,
            run: detectors::bypass01_hosts::run,
        },
        DetectorMeta {
            code: "bypass02_restricted_sites",
            id: 2,
            run: detectors::bypass02_restricted_sites::run,
        },
        DetectorMeta {
            code: "bypass03_disallowrun",
            id: 3,
            run: detectors::bypass03_disallowrun::run,
        },
        DetectorMeta {
            code: "bypass04_fake_signature",
            id: 4,
            run: detectors::bypass04_fake_signature::run,
        },
        DetectorMeta {
            code: "bypass05_service_threads",
            id: 5,
            run: detectors::bypass05_service_threads::run,
        },
        DetectorMeta {
            code: "bypass06_timestomp",
            id: 6,
            run: detectors::bypass06_timestomp::run,
        },
        DetectorMeta {
            code: "bypass07_app_blockers",
            id: 7,
            run: detectors::bypass07_app_blockers::run,
        },
        DetectorMeta {
            code: "bypass08_legacy_console",
            id: 8,
            run: detectors::bypass08_legacy_console::run,
        },
        DetectorMeta {
            code: "bypass09_prefetch_rename",
            id: 9,
            run: detectors::bypass09_prefetch_rename::run,
        },
        DetectorMeta {
            code: "bypass10_stego",
            id: 10,
            run: detectors::bypass10_stego::run,
        },
        DetectorMeta {
            code: "bypass11_hidden_cmd_text",
            id: 11,
            run: detectors::bypass11_hidden_cmd_text::run,
        },
        DetectorMeta {
            code: "bypass12_extension_spoof",
            id: 12,
            run: detectors::bypass12_extension_spoof::run,
        },
        DetectorMeta {
            code: "bypass13_prefetch_attrib",
            id: 13,
            run: detectors::bypass13_prefetch_attrib::run,
        },
        DetectorMeta {
            code: "bypass14_eventlog_clear",
            id: 14,
            run: detectors::bypass14_eventlog_clear::run,
        },
        DetectorMeta {
            code: "bypass15_usn_clear",
            id: 15,
            run: detectors::bypass15_usn_clear::run,
        },
        DetectorMeta {
            code: "bypass16_file_wiping",
            id: 16,
            run: detectors::bypass16_file_wiping::run,
        },
        DetectorMeta {
            code: "bypass17_registry_usb_deletion",
            id: 17,
            run: detectors::bypass17_registry_usb_deletion::run,
        },
        DetectorMeta {
            code: "bypass18_prefetch_amcache_wipe",
            id: 18,
            run: detectors::bypass18_prefetch_amcache_wipe::run,
        },
        DetectorMeta {
            code: "bypass19_browser_cache_wipe",
            id: 19,
            run: detectors::bypass19_browser_cache_wipe::run,
        },
        DetectorMeta {
            code: "bypass20_shadowcopy_delete",
            id: 20,
            run: detectors::bypass20_shadowcopy_delete::run,
        },
        DetectorMeta {
            code: "bypass21_pagefile_hiber_wipe",
            id: 21,
            run: detectors::bypass21_pagefile_hiber_wipe::run,
        },
        DetectorMeta {
            code: "bypass22_thumbnail_cache_delete",
            id: 22,
            run: detectors::bypass22_thumbnail_cache_delete::run,
        },
        DetectorMeta {
            code: "bypass24_covert_channels",
            id: 24,
            run: detectors::bypass24_covert_channels::run,
        },
        DetectorMeta {
            code: "bypass25_ram_disk",
            id: 25,
            run: detectors::bypass25_ram_disk::run,
        },
        DetectorMeta {
            code: "bypass26_log_flooding",
            id: 26,
            run: detectors::bypass26_log_flooding::run,
        },
        DetectorMeta {
            code: "bypass27_usb_policy_disable",
            id: 27,
            run: detectors::bypass27_usb_policy_disable::run,
        },
        DetectorMeta {
            code: "bypass28_wef_tamper",
            id: 28,
            run: detectors::bypass28_wef_tamper::run,
        },
        DetectorMeta {
            code: "bypass29_restore_point_removal",
            id: 29,
            run: detectors::bypass29_restore_point_removal::run,
        },
        DetectorMeta {
            code: "bypass30_trim_tamper",
            id: 30,
            run: detectors::bypass30_trim_tamper::run,
        },
        DetectorMeta {
            code: "bypass31_polyglot_append",
            id: 31,
            run: detectors::bypass31_polyglot_append::run,
        },
        DetectorMeta {
            code: "bypass32_fileless_amsi_lolbins",
            id: 32,
            run: detectors::bypass32_fileless_amsi_lolbins::run,
        },
        DetectorMeta {
            code: "bypass33_container_prune",
            id: 33,
            run: detectors::bypass33_container_prune::run,
        },
        DetectorMeta {
            code: "bypass34_cloud_sync_delete",
            id: 34,
            run: detectors::bypass34_cloud_sync_delete::run,
        },
        DetectorMeta {
            code: "bypass35_exif_timestamp_edit",
            id: 35,
            run: detectors::bypass35_exif_timestamp_edit::run,
        },
        DetectorMeta {
            code: "bypass37_fake_usb_artifacts",
            id: 37,
            run: detectors::bypass37_fake_usb_artifacts::run,
        },
        DetectorMeta {
            code: "bypass38_mac_randomization",
            id: 38,
            run: detectors::bypass38_mac_randomization::run,
        },
        DetectorMeta {
            code: "bypass39_dns_fuzzing",
            id: 39,
            run: detectors::bypass39_dns_fuzzing::run,
        },
        DetectorMeta {
            code: "bypass40_secure_boot_tamper",
            id: 40,
            run: detectors::bypass40_secure_boot_tamper::run,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::strict_flag_from_value;

    #[test]
    fn strict_flag_defaults_to_enabled() {
        assert!(strict_flag_from_value(None));
        assert!(strict_flag_from_value(Some("1".to_string())));
        assert!(strict_flag_from_value(Some("true".to_string())));
    }

    #[test]
    fn strict_flag_parses_disable_values() {
        assert!(!strict_flag_from_value(Some("0".to_string())));
        assert!(!strict_flag_from_value(Some("false".to_string())));
        assert!(!strict_flag_from_value(Some("off".to_string())));
        assert!(!strict_flag_from_value(Some("no".to_string())));
    }
}
