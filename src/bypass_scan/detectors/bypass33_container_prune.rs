use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, prefetch_file_names_by_prefixes, query_event_records, run_command, truncate_text,
};

const CONTAINER_PREFIXES: &[&str] = &["DOCKER.EXE-", "PODMAN.EXE-", "WSL.EXE-"];

pub fn run(_ctx: &crate::bypass_scan::context::ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        33,
        "bypass33_container_prune",
        "Container trace cleanup (Docker/WSL/Podman)",
        "No explicit container-prune or unregister tamper commands found.",
    );

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        220,
    );
    let sec_events = query_event_records("Security", &[4688], 320);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 220);
    let command_hits = collect_container_cleanup_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    let prefetch = prefetch_file_names_by_prefixes(CONTAINER_PREFIXES);
    let inventory = query_container_inventory();

    if command_hits.len() >= 2 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected explicit container cleanup commands that remove runtime traces/artifacts."
                .to_string();
    } else if command_hits.len() == 1 && inventory.looks_recently_wiped() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Single container cleanup command correlates with near-empty container/runtime inventory."
                .to_string();
    } else if command_hits.len() == 1 {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Single container cleanup command observed; validate whether it was legitimate maintenance."
                .to_string();
    } else if inventory.looks_recently_wiped() && !prefetch.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Container tooling execution traces exist with empty runtime inventory (possible cleanup)."
                .to_string();
    }

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} container cleanup command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if !prefetch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: r"C:\Windows\Prefetch".to_string(),
            summary: format!("{} related prefetch file(s)", prefetch.len()),
            details: prefetch.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "Container runtime inventory".to_string(),
        summary: format!(
            "docker_ps={} docker_images={} docker_volumes={} wsl_distros={} podman_containers={} podman_images={}",
            inventory.docker_ps_count,
            inventory.docker_image_count,
            inventory.docker_volume_count,
            inventory.wsl_distro_count,
            inventory.podman_container_count,
            inventory.podman_image_count,
        ),
        details: format!(
            "docker_ps='{}' | docker_images='{}' | wsl='{}'",
            truncate_text(&inventory.docker_ps_raw, 180),
            truncate_text(&inventory.docker_images_raw, 180),
            truncate_text(&inventory.wsl_raw, 180),
        ),
    });

    logger.log(
        "bypass33_container_prune",
        "info",
        "container checks complete",
        serde_json::json!({
            "command_hits": command_hits.len(),
            "prefetch": prefetch.len(),
            "docker_ps_count": inventory.docker_ps_count,
            "docker_image_count": inventory.docker_image_count,
            "docker_volume_count": inventory.docker_volume_count,
            "wsl_distro_count": inventory.wsl_distro_count,
            "podman_container_count": inventory.podman_container_count,
            "podman_image_count": inventory.podman_image_count,
            "status": result.status.as_label(),
        }),
    );

    result
}

fn collect_container_cleanup_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut hits = Vec::new();
    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_container_cleanup_command(&normalized) {
                continue;
            }
            hits.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 220)
            ));
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

fn looks_like_container_cleanup_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    let docker_prune = normalized.contains("docker")
        && (normalized.contains(" system prune")
            || normalized.contains(" builder prune")
            || normalized.contains(" image prune")
            || normalized.contains(" volume prune")
            || normalized.contains(" container prune")
            || (normalized.contains("compose down") && normalized.contains("-v")));
    let podman_prune = normalized.contains("podman")
        && (normalized.contains(" system prune")
            || normalized.contains(" image prune")
            || normalized.contains(" volume prune")
            || normalized.contains(" rm "));
    let wsl_remove = normalized.contains("wsl")
        && (normalized.contains("--unregister") || normalized.contains("--uninstall"));
    docker_prune || podman_prune || wsl_remove
}

#[derive(Debug, Clone)]
struct ContainerInventory {
    docker_ps_count: usize,
    docker_image_count: usize,
    docker_volume_count: usize,
    wsl_distro_count: usize,
    podman_container_count: usize,
    podman_image_count: usize,
    docker_ps_raw: String,
    docker_images_raw: String,
    wsl_raw: String,
}

impl ContainerInventory {
    fn looks_recently_wiped(&self) -> bool {
        (self.docker_ps_count == 0 && self.docker_image_count == 0 && self.docker_volume_count == 0)
            || (self.podman_container_count == 0 && self.podman_image_count == 0)
            || self.wsl_distro_count == 0
    }
}

fn query_container_inventory() -> ContainerInventory {
    let docker_ps_raw =
        run_command("docker", &["ps", "-a", "--format", "{{.ID}}"]).unwrap_or_default();
    let docker_images_raw = run_command("docker", &["images", "-q"]).unwrap_or_default();
    let docker_volume_raw = run_command("docker", &["volume", "ls", "-q"]).unwrap_or_default();
    let wsl_raw = run_command("wsl", &["-l", "-q"]).unwrap_or_default();
    let podman_ps_raw =
        run_command("podman", &["ps", "-a", "--format", "{{.ID}}"]).unwrap_or_default();
    let podman_images_raw = run_command("podman", &["images", "-q"]).unwrap_or_default();

    ContainerInventory {
        docker_ps_count: count_nonempty_lines(&docker_ps_raw),
        docker_image_count: count_nonempty_lines(&docker_images_raw),
        docker_volume_count: count_nonempty_lines(&docker_volume_raw),
        wsl_distro_count: count_nonempty_lines(&wsl_raw),
        podman_container_count: count_nonempty_lines(&podman_ps_raw),
        podman_image_count: count_nonempty_lines(&podman_images_raw),
        docker_ps_raw,
        docker_images_raw,
        wsl_raw,
    }
}

fn count_nonempty_lines(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::{count_nonempty_lines, looks_like_container_cleanup_command};

    #[test]
    fn cleanup_matcher_catches_docker_and_wsl_cleanup() {
        assert!(looks_like_container_cleanup_command(
            "docker system prune -af --volumes"
        ));
        assert!(looks_like_container_cleanup_command(
            "wsl --unregister Ubuntu"
        ));
        assert!(!looks_like_container_cleanup_command("docker ps -a"));
    }

    #[test]
    fn nonempty_line_counter_ignores_blanks() {
        assert_eq!(count_nonempty_lines("a\n\n b \n"), 2);
        assert_eq!(count_nonempty_lines("\n \n"), 0);
    }
}
