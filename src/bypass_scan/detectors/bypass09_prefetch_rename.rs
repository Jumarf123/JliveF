use std::fs;
use std::path::Path;

use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::is_maybe_prefetch_name;

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        9,
        "bypass09_prefetch_rename",
        "Prefetch folder look-alike rename",
        "Prefetch folder name looks normal.",
    );

    let windows_dir = Path::new(r"C:\Windows");
    let Ok(entries) = fs::read_dir(windows_dir) else {
        result.status = DetectionStatus::Error;
        result.summary = "Failed to read C:\\Windows directory".to_string();
        result.error = Some("read_dir failed".to_string());
        return result;
    };

    let mut exact_exists = false;
    let mut lookalikes = Vec::new();

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        if name.eq_ignore_ascii_case("Prefetch") {
            exact_exists = true;
        }
        if is_maybe_prefetch_name(&name) {
            lookalikes.push(name);
        }
    }

    let non_exact_lookalikes = lookalikes.iter().cloned().collect::<Vec<_>>();
    let non_exact_lookalikes = non_exact_prefetch_lookalikes(&non_exact_lookalikes);

    if !exact_exists && !non_exact_lookalikes.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Canonical Prefetch folder missing while confusable look-alike exists.".to_string();
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows".to_string(),
            summary: format!("{} confusable folder(s)", non_exact_lookalikes.len()),
            details: non_exact_lookalikes.join("; "),
        });
        result.recommendations.push(
            "Restore canonical C:\\Windows\\Prefetch naming and preserve filesystem timeline evidence."
                .to_string(),
        );
    } else if !non_exact_lookalikes.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Confusable Prefetch-like folder names exist beside canonical path.".to_string();
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows".to_string(),
            summary: format!(
                "{} additional look-alike folder(s)",
                non_exact_lookalikes.len()
            ),
            details: non_exact_lookalikes.join("; "),
        });
    }

    logger.log(
        "bypass09_prefetch_rename",
        "info",
        "prefetch rename check complete",
        serde_json::json!({
            "exact_exists": exact_exists,
            "lookalikes": lookalikes,
        }),
    );

    result
}

fn non_exact_prefetch_lookalikes(lookalikes: &[String]) -> Vec<String> {
    lookalikes
        .iter()
        .filter(|name| !name.eq_ignore_ascii_case("Prefetch"))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::non_exact_prefetch_lookalikes;

    #[test]
    fn strips_canonical_prefetch_name() {
        let input = vec![
            "Prefetch".to_string(),
            "prefetch".to_string(),
            "Рrefetch".to_string(),
        ];
        let filtered = non_exact_prefetch_lookalikes(&input);
        assert_eq!(filtered, vec!["Рrefetch".to_string()]);
    }
}
