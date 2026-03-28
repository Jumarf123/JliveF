use std::collections::HashMap;

use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, truncate_text,
};

const EVENTCREATE_PREFIX: &[&str] = &["EVENTCREATE.EXE-"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        26,
        "bypass26_log_flooding",
        "Event log flooding (eventcreate spam)",
        "No high-confidence event-flooding pattern found.",
    );

    let eventcreate_prefetch = prefetch_file_names_by_prefixes(EVENTCREATE_PREFIX);
    let mut app_events = query_event_records("Application", &[1], 1200);
    app_events.extend(query_event_records("System", &[1], 600));
    let burst = compute_peak_burst_stats(&app_events);

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 240);
    let command_hits = collect_eventcreate_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_events),
    ]);

    if !command_hits.is_empty()
        && burst.total >= 25
        && burst.dominant_provider_ratio >= 0.7
        && burst.unique_message_ratio <= 0.6
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected eventcreate command traces with concentrated EventID=1 burst pattern."
                .to_string();
    } else if burst.total >= 80
        && burst.dominant_provider_ratio >= 0.8
        && burst.unique_message_ratio <= 0.4
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Strong EventID=1 burst pattern detected, but no direct eventcreate command trace."
                .to_string();
    } else if !command_hits.is_empty() && burst.total >= 15 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Eventcreate command traces found with moderate EventID=1 burst activity.".to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Detected eventcreate command traces without strong burst confirmation.".to_string();
    } else if !eventcreate_prefetch.is_empty() && burst.total >= 30 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "EVENTCREATE execution traces exist with elevated EventID=1 volume; validate intent."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} eventcreate command trace(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !eventcreate_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!(
                "{} EVENTCREATE prefetch file(s)",
                eventcreate_prefetch.len()
            ),
            details: eventcreate_prefetch.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Application/System EventID 1 burst analysis".to_string(),
        summary: format!(
            "peak_total={} bucket={} dominant_provider={} ratio={:.2} unique_message_ratio={:.2}",
            burst.total,
            burst.bucket_key,
            burst.dominant_provider,
            burst.dominant_provider_ratio,
            burst.unique_message_ratio
        ),
        details: truncate_text(&burst.sample_messages.join(" | "), 500),
    });

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Correlate burst window with process lineage and host activity to separate synthetic flooding from legitimate service storms."
                .to_string(),
        );
    }

    logger.log(
        "bypass26_log_flooding",
        "info",
        "log flooding checks complete",
        serde_json::json!({
            "eventcreate_prefetch": eventcreate_prefetch.len(),
            "command_hits": command_hits.len(),
            "peak_total": burst.total,
            "bucket_key": burst.bucket_key,
            "dominant_provider": burst.dominant_provider,
            "dominant_provider_ratio": burst.dominant_provider_ratio,
            "unique_message_ratio": burst.unique_message_ratio,
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone)]
struct BurstStats {
    total: usize,
    bucket_key: String,
    dominant_provider: String,
    dominant_provider_ratio: f64,
    unique_message_ratio: f64,
    sample_messages: Vec<String>,
}

fn compute_peak_burst_stats(events: &[EventRecord]) -> BurstStats {
    #[derive(Default)]
    struct BucketAccumulator {
        total: usize,
        provider_counts: HashMap<String, usize>,
        message_counts: HashMap<String, usize>,
        sample_messages: Vec<String>,
    }

    let mut buckets: HashMap<String, BucketAccumulator> = HashMap::new();

    for ev in events {
        let Ok(ts) = DateTime::parse_from_rfc3339(&ev.time_created) else {
            continue;
        };
        let ts = ts.with_timezone(&Utc);
        let minute_bucket = (ts.minute() / 5) * 5;
        let key = format!(
            "{}-{:02}-{:02} {:02}:{:02}",
            ts.year(),
            ts.month(),
            ts.day(),
            ts.hour(),
            minute_bucket
        );

        let entry = buckets.entry(key).or_default();
        entry.total += 1;
        *entry
            .provider_counts
            .entry(ev.provider.to_lowercase())
            .or_insert(0) += 1;

        let normalized_message = truncate_text(&ev.message.to_lowercase(), 120);
        *entry.message_counts.entry(normalized_message).or_insert(0) += 1;

        if entry.sample_messages.len() < 5 {
            entry.sample_messages.push(format!(
                "{} | {}",
                ev.provider,
                truncate_text(&ev.message, 120)
            ));
        }
    }

    let Some((bucket_key, peak)) = buckets.into_iter().max_by_key(|(_, acc)| acc.total) else {
        return BurstStats {
            total: 0,
            bucket_key: "n/a".to_string(),
            dominant_provider: "n/a".to_string(),
            dominant_provider_ratio: 0.0,
            unique_message_ratio: 1.0,
            sample_messages: Vec::new(),
        };
    };

    let (dominant_provider, dominant_provider_count) = peak
        .provider_counts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(provider, count)| (provider.clone(), *count))
        .unwrap_or_else(|| ("n/a".to_string(), 0));

    let total = peak.total.max(1);
    let dominant_provider_ratio = dominant_provider_count as f64 / total as f64;
    let unique_message_ratio = peak.message_counts.len() as f64 / total as f64;

    BurstStats {
        total: peak.total,
        bucket_key,
        dominant_provider,
        dominant_provider_ratio,
        unique_message_ratio,
        sample_messages: peak.sample_messages,
    }
}

fn collect_eventcreate_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_eventcreate_command(&normalized) {
                continue;
            }

            hits.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220),
            ));
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

fn looks_like_eventcreate_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    normalized.contains("eventcreate")
        && normalized.contains("/id")
        && normalized.contains("/d")
        && (normalized.contains("/l application") || normalized.contains("/l system"))
}

#[cfg(test)]
mod tests {
    use super::{compute_peak_burst_stats, looks_like_eventcreate_command};
    use crate::bypass_scan::utils::EventRecord;

    #[test]
    fn eventcreate_matcher_requires_cli_shape() {
        assert!(looks_like_eventcreate_command(
            "eventcreate /t information /id 1 /l application /so test /d hello"
        ));
        assert!(looks_like_eventcreate_command(
            "eventcreate /t warning /id 5 /l system /so test /d hello"
        ));
        assert!(!looks_like_eventcreate_command("eventcreate.exe /?"));
        assert!(!looks_like_eventcreate_command(
            "eventcreate /t information /l application /so test"
        ));
    }

    #[test]
    fn burst_stats_detect_provider_concentration() {
        let events = vec![
            EventRecord {
                event_id: 1,
                provider: "testsrc".to_string(),
                time_created: "2026-03-01T01:00:01Z".to_string(),
                message: "spam".to_string(),
                raw_xml: String::new(),
            },
            EventRecord {
                event_id: 1,
                provider: "testsrc".to_string(),
                time_created: "2026-03-01T01:01:01Z".to_string(),
                message: "spam".to_string(),
                raw_xml: String::new(),
            },
            EventRecord {
                event_id: 1,
                provider: "testsrc".to_string(),
                time_created: "2026-03-01T01:02:01Z".to_string(),
                message: "spam".to_string(),
                raw_xml: String::new(),
            },
        ];
        let stats = compute_peak_burst_stats(&events);
        assert_eq!(stats.total, 3);
        assert!(stats.dominant_provider_ratio > 0.9);
        assert!(stats.unique_message_ratio < 0.5);
    }
}
