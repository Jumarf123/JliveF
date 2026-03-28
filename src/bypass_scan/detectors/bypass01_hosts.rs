use std::fs;
use std::path::Path;

use crate::bypass_scan::keywords::contains_domain_keyword;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        1,
        "bypass01_hosts",
        "Hosts file site blocking",
        "No suspicious hosts overrides detected.",
    );

    let hosts_path = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
    let content = match fs::read_to_string(hosts_path) {
        Ok(content) => content,
        Err(err) => {
            result.status = DetectionStatus::Error;
            result.confidence = Confidence::Low;
            result.summary = format!("Failed to read hosts file: {err}");
            result.error = Some(err.to_string());
            return result;
        }
    };

    let active_lines = collect_active_hosts_lines(&content);
    if active_lines.is_empty() {
        return result;
    }

    let entries = parse_hosts_entries(&active_lines);
    let mut high_conf_hits = Vec::new();
    for entry in &entries {
        if contains_domain_keyword(entry) && entry_uses_block_redirect_ip(entry) {
            high_conf_hits.push(entry.clone());
        }
    }

    result.status = DetectionStatus::Detected;
    if !high_conf_hits.is_empty() {
        result.confidence = Confidence::High;
        result.summary =
            "Hosts contains explicit blocking entries targeting scan/forensic domains.".to_string();
        result.evidence.push(EvidenceItem {
            source: hosts_path.display().to_string(),
            summary: format!("{} active non-comment line(s) found", active_lines.len()),
            details: active_lines.join("; "),
        });
        result.evidence.push(EvidenceItem {
            source: hosts_path.display().to_string(),
            summary: format!("{} targeted host mappings found", high_conf_hits.len()),
            details: high_conf_hits.join("; "),
        });
        result.recommendations.push(
            "Remove unauthorized mappings from hosts file and keep only approved entries."
                .to_string(),
        );
    } else {
        result.confidence = Confidence::Low;
        result.summary = "Hosts contains active non-comment entries (policy: any active entry is bypass indicator).".to_string();
        result.evidence.push(EvidenceItem {
            source: hosts_path.display().to_string(),
            summary: format!("{} active non-comment line(s) found", active_lines.len()),
            details: active_lines.join("; "),
        });
        result.evidence.push(EvidenceItem {
            source: hosts_path.display().to_string(),
            summary: format!("{} parsed host mapping(s) found", entries.len()),
            details: if entries.is_empty() {
                "No valid host mappings parsed, but active non-comment lines exist.".to_string()
            } else {
                entries.join("; ")
            },
        });
        result.recommendations.push(
            "Review whether these hosts mappings are corporate policy or tampering.".to_string(),
        );
    }

    logger.log(
        "bypass01_hosts",
        "info",
        "hosts analyzed",
        serde_json::json!({
            "active_lines": active_lines.len(),
            "parsed_mappings": entries.len(),
            "targeted_hits": high_conf_hits.len(),
        }),
    );

    result
}

fn collect_active_hosts_lines(content: &str) -> Vec<String> {
    let mut out = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() {
            continue;
        }
        // Comment line only when '#' is the first non-space character.
        if line
            .trim_start_matches('\u{feff}')
            .trim_start()
            .starts_with('#')
        {
            continue;
        }
        out.push(trimmed.to_string());
    }

    out
}

fn parse_hosts_entries(active_lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();

    for line in active_lines {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }

        let ip = parts[0].trim_start_matches('\u{feff}');
        for host in &parts[1..] {
            // Inline comment tail: ignore everything after the first token that starts with '#'.
            let host_clean = host.trim_start_matches('\u{feff}');
            if host_clean.starts_with('#') {
                break;
            }
            let host_l = host_clean.to_lowercase();
            out.push(format!("{ip} -> {host_l}"));
        }
    }

    out
}

fn entry_uses_block_redirect_ip(entry: &str) -> bool {
    let Some((ip, _host)) = entry.split_once("->") else {
        return false;
    };
    let ip = ip.trim();
    matches!(ip, "0.0.0.0" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::{collect_active_hosts_lines, entry_uses_block_redirect_ip, parse_hosts_entries};

    #[test]
    fn hosts_parser_ignores_only_lines_where_hash_is_first_non_space_char() {
        let sample = format!(
            r#"
# comment
   # another comment
{}
127.0.0.1 localhost
0.0.0.0 bad.example
"#,
            "\u{feff}# bom comment"
        );
        let active = collect_active_hosts_lines(&sample);
        assert_eq!(active.len(), 2);
        assert!(active[0].contains("127.0.0.1 localhost"));
        assert!(active[1].contains("bad.example"));
    }

    #[test]
    fn hosts_parser_returns_mappings_from_active_lines() {
        let active = vec![
            "127.0.0.1 localhost".to_string(),
            "0.0.0.0 bad.example".to_string(),
        ];
        let entries = parse_hosts_entries(&active);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.contains("localhost")));
        assert!(entries.iter().any(|e| e.contains("bad.example")));
    }

    #[test]
    fn hosts_parser_ignores_inline_comment_tail() {
        let active = vec!["0.0.0.0 bad.example # note".to_string()];
        let entries = parse_hosts_entries(&active);
        assert_eq!(entries, vec!["0.0.0.0 -> bad.example".to_string()]);
    }

    #[test]
    fn high_conf_block_ip_matcher_accepts_loopback_or_null_routes_only() {
        assert!(entry_uses_block_redirect_ip("0.0.0.0 -> bad.example"));
        assert!(entry_uses_block_redirect_ip("127.0.0.1 -> bad.example"));
        assert!(entry_uses_block_redirect_ip("::1 -> bad.example"));
        assert!(!entry_uses_block_redirect_ip("10.0.0.10 -> corp.portal"));
    }
}
