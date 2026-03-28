use std::collections::{HashMap, HashSet};

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, extract_event_data_value, prefetch_file_names_by_prefixes, query_event_records,
    truncate_text,
};

const DNS_TOOL_PREFIXES: &[&str] = &["DNSCAT", "IODINE", "DNS2TCP", "NSLOOKUP.EXE-"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        39,
        "bypass39_dns_fuzzing",
        "DNS tunneling / DGA-style fuzzing",
        "No high-confidence DNS tunneling tool evidence found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        260,
    );
    let sec_events = query_event_records("Security", &[4688], 340);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 260);
    let command_hits = collect_dns_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let dns_client_events = query_event_records(
        "Microsoft-Windows-DNS-Client/Operational",
        &[3008, 3010],
        420,
    );
    let dns_stats = analyze_dns_events(&dns_client_events);

    let sysmon_net_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[3], 420);
    let dns_net_hits = collect_dns_network_hits(&sysmon_net_events);

    let tool_prefetch = prefetch_file_names_by_prefixes(DNS_TOOL_PREFIXES);

    let strong_tool_hits = command_hits
        .iter()
        .filter(|h| matches!(h.kind, DnsCommandKind::ExplicitTool))
        .count();
    let weak_txt_hits = command_hits
        .iter()
        .filter(|h| matches!(h.kind, DnsCommandKind::TxtBurstStyle))
        .count();

    if strong_tool_hits >= 1
        && (!dns_net_hits.is_empty()
            || dns_stats.high_entropy_count >= 8
            || dns_stats.repeated_suffix_max_count >= 4)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "DNS tunneling-tool commands correlate with suspicious DNS query/network patterns."
                .to_string();
    } else if strong_tool_hits >= 1 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary = "Detected explicit DNS tunneling-tool command traces.".to_string();
    } else if weak_txt_hits >= 3
        && dns_stats.high_entropy_count >= 8
        && (dns_stats.repeated_suffix_max_count >= 3 || dns_stats.nxdomain_like_count >= 10)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Repeated TXT-query command pattern correlates with high-entropy DNS query burst."
                .to_string();
    } else if (dns_stats.high_entropy_count >= 20 && dns_stats.repeated_suffix_max_count >= 4)
        || (dns_stats.nxdomain_like_count >= 25 && dns_stats.high_entropy_count >= 10)
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "DNS-client logs show strong high-entropy / NXDOMAIN-like burst pattern (possible DGA/tunnel)."
                .to_string();
    } else if dns_net_hits.len() >= 3
        || (weak_txt_hits >= 1 && dns_stats.high_entropy_count >= 3)
        || (dns_stats.high_entropy_count >= 10 && dns_stats.repeated_suffix_max_count >= 3)
        || (!tool_prefetch.is_empty()
            && (dns_stats.high_entropy_count >= 3 || dns_stats.nxdomain_like_count >= 10))
    {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Early DNS tunneling indicators detected (low confidence); validate against baseline."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} DNS-related command hit(s)", command_hits.len()),
            details: command_hits
                .iter()
                .map(|h| h.line.clone())
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    if !dns_stats.high_entropy_domains.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Microsoft-Windows-DNS-Client/Operational".to_string(),
            summary: format!(
                "{} high-entropy domain(s), suspicious_events={}, nxdomain_like={}, repeated_suffix_max={}",
                dns_stats.high_entropy_count,
                dns_stats.suspicious_event_count,
                dns_stats.nxdomain_like_count,
                dns_stats.repeated_suffix_max_count
            ),
            details: dns_stats.high_entropy_domains.join("; "),
        });
    }

    if !dns_net_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Sysmon EventID 3".to_string(),
            summary: format!("{} DNS/tunnel-like network event(s)", dns_net_hits.len()),
            details: dns_net_hits.join("; "),
        });
    }

    if !tool_prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} related tool prefetch file(s)", tool_prefetch.len()),
            details: tool_prefetch.join("; "),
        });
    }

    logger.log(
        "bypass39_dns_fuzzing",
        "info",
        "dns fuzzing checks complete",
        serde_json::json!({
            "strong_tool_hits": strong_tool_hits,
            "weak_txt_hits": weak_txt_hits,
            "high_entropy_count": dns_stats.high_entropy_count,
            "suspicious_event_count": dns_stats.suspicious_event_count,
            "nxdomain_like_count": dns_stats.nxdomain_like_count,
            "repeated_suffix_max_count": dns_stats.repeated_suffix_max_count,
            "dns_net_hits": dns_net_hits.len(),
            "tool_prefetch": tool_prefetch.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsCommandKind {
    ExplicitTool,
    TxtBurstStyle,
}

#[derive(Debug, Clone)]
struct DnsCommandHit {
    kind: DnsCommandKind,
    line: String,
}

fn collect_dns_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<DnsCommandHit> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let text = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            let kind = classify_dns_command(&text);
            let Some(kind) = kind else {
                continue;
            };
            hits.push(DnsCommandHit {
                kind,
                line: format!(
                    "{} | {} Event {} | {}",
                    event.time_created,
                    source,
                    event.event_id,
                    truncate_text(&event.message, 220),
                ),
            });
        }
    }
    hits.sort_by(|a, b| a.line.cmp(&b.line));
    hits.dedup_by(|a, b| a.kind == b.kind && a.line == b.line);
    hits
}

fn classify_dns_command(text: &str) -> Option<DnsCommandKind> {
    let normalized = text.to_lowercase();
    if normalized.contains("dnscat")
        || normalized.contains("iodine")
        || normalized.contains("dns2tcp")
        || normalized.contains("dnstun")
    {
        return Some(DnsCommandKind::ExplicitTool);
    }

    let txt_query = normalized.contains("nslookup")
        && (normalized.contains("-q=txt") || normalized.contains("-type=txt"))
        && (normalized.contains('.') || normalized.contains("http"));
    if txt_query {
        return Some(DnsCommandKind::TxtBurstStyle);
    }

    None
}

#[derive(Debug, Clone)]
struct DnsStats {
    high_entropy_count: usize,
    suspicious_event_count: usize,
    nxdomain_like_count: usize,
    repeated_suffix_max_count: usize,
    high_entropy_domains: Vec<String>,
}

fn analyze_dns_events(events: &[EventRecord]) -> DnsStats {
    let mut domains = HashSet::new();
    let mut nxdomain_like_count = 0usize;
    let mut suspicious_event_count = 0usize;
    let mut suffix_counts: HashMap<String, usize> = HashMap::new();

    for event in events {
        let query_name = extract_event_data_value(&event.raw_xml, "QueryName")
            .or_else(|| extract_event_data_value(&event.raw_xml, "Name"))
            .unwrap_or_default()
            .to_lowercase();
        if !query_name.is_empty() && is_suspicious_domain(&query_name) {
            suspicious_event_count += 1;
            domains.insert(query_name.clone());
            if let Some((_, suffix)) = query_name.split_once('.') {
                *suffix_counts.entry(suffix.to_string()).or_insert(0) += 1;
            }
        }

        let msg = format!("{} {}", event.message, event.raw_xml).to_lowercase();
        if msg.contains("nxdomain")
            || msg.contains("name does not exist")
            || msg.contains("no such name")
            || msg.contains("error 9003")
        {
            nxdomain_like_count += 1;
        }
    }

    let mut high_entropy_domains = domains.into_iter().collect::<Vec<_>>();
    high_entropy_domains.sort();
    high_entropy_domains.truncate(40);
    let repeated_suffix_max_count = suffix_counts.values().copied().max().unwrap_or(0);

    DnsStats {
        high_entropy_count: high_entropy_domains.len(),
        suspicious_event_count,
        nxdomain_like_count,
        repeated_suffix_max_count,
        high_entropy_domains,
    }
}

fn collect_dns_network_hits(events: &[EventRecord]) -> Vec<String> {
    let mut hits = Vec::new();

    for event in events {
        let port = extract_event_data_value(&event.raw_xml, "DestinationPort")
            .unwrap_or_default()
            .trim()
            .to_string();
        if port != "53" && port != "5353" {
            continue;
        }

        let image = extract_event_data_value(&event.raw_xml, "Image")
            .unwrap_or_default()
            .to_lowercase();
        let command_line = extract_event_data_value(&event.raw_xml, "CommandLine")
            .unwrap_or_default()
            .to_lowercase();
        let destination_hostname = extract_event_data_value(&event.raw_xml, "DestinationHostname")
            .unwrap_or_default()
            .to_lowercase();
        let msg = format!("{} {}", event.message, event.raw_xml).to_lowercase();

        let explicit_tool = ["dnscat", "iodine", "dns2tcp", "dnstun"]
            .iter()
            .any(|needle| {
                image.contains(needle) || command_line.contains(needle) || msg.contains(needle)
            });
        let scripted_process = [
            "nslookup",
            "powershell",
            "pwsh",
            "cmd.exe",
            "python",
            "wscript",
            "cscript",
        ]
        .iter()
        .any(|needle| image.contains(needle) || command_line.contains(needle));
        let txt_query_shape = command_line.contains("nslookup")
            && (command_line.contains("-q=txt") || command_line.contains("-type=txt"));
        let suspicious_host = !destination_hostname.is_empty()
            && is_suspicious_domain(destination_hostname.trim_end_matches('.'));

        if !(explicit_tool || txt_query_shape || (scripted_process && suspicious_host)) {
            continue;
        }

        hits.push(format!(
            "{} | Event {} | port={} image={} host={} msg={}",
            event.time_created,
            event.event_id,
            port,
            truncate_text(&image, 80),
            truncate_text(&destination_hostname, 120),
            truncate_text(&event.message, 160),
        ));
    }

    hits.sort();
    hits.dedup();
    hits
}

fn is_suspicious_domain(domain: &str) -> bool {
    if domain.len() < 20 || domain.len() > 120 {
        return false;
    }

    let first_label = domain.split('.').next().unwrap_or_default();
    if first_label.len() < 14 {
        return false;
    }

    let entropy = shannon_entropy(first_label);
    entropy >= 3.6 && first_label.chars().any(|c| c.is_ascii_digit())
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = HashMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }

    let len = value.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::collect_dns_network_hits;
    use super::{DnsCommandKind, classify_dns_command, is_suspicious_domain, shannon_entropy};
    use crate::bypass_scan::utils::EventRecord;

    #[test]
    fn dns_command_classifier_detects_tools_and_txt_shape() {
        assert_eq!(
            classify_dns_command("dnscat2 --dns server"),
            Some(DnsCommandKind::ExplicitTool)
        );
        assert_eq!(
            classify_dns_command("nslookup -q=txt abcdefghijklmn123.example.com"),
            Some(DnsCommandKind::TxtBurstStyle)
        );
        assert_eq!(classify_dns_command("nslookup example.com"), None);
    }

    #[test]
    fn suspicious_domain_uses_entropy_and_length() {
        assert!(is_suspicious_domain(
            "a8f4d9k2m1q0z7x6c5v4b3n2m1.example.com"
        ));
        assert!(!is_suspicious_domain("cdn.microsoft.com"));
        assert!(shannon_entropy("abcdefgh") > 2.5);
    }

    #[test]
    fn dns_network_hits_require_suspicious_shape() {
        let suspicious = EventRecord {
            event_id: 3,
            provider: "Sysmon".to_string(),
            time_created: "2026-03-01T00:00:00Z".to_string(),
            message: "Network connection detected".to_string(),
            raw_xml: "<Event><EventData><Data Name=\"DestinationPort\">53</Data><Data Name=\"Image\">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name=\"DestinationHostname\">a8f4d9k2m1q0z7x6c5v4b3n2m1.example.com</Data></EventData></Event>".to_string(),
        };
        let benign = EventRecord {
            event_id: 3,
            provider: "Sysmon".to_string(),
            time_created: "2026-03-01T00:00:01Z".to_string(),
            message: "Network connection detected".to_string(),
            raw_xml: "<Event><EventData><Data Name=\"DestinationPort\">53</Data><Data Name=\"Image\">C:\\Windows\\System32\\svchost.exe</Data><Data Name=\"DestinationHostname\">microsoft.com</Data></EventData></Event>".to_string(),
        };

        let hits = collect_dns_network_hits(&[suspicious, benign]);
        assert_eq!(hits.len(), 1);
    }
}
