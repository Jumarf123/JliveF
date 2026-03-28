use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use rayon::prelude::*;
use windows::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
    CERT_E_UNTRUSTEDTESTROOT, HWND, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST,
    TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_UI_NONE, WinVerifyTrust,
};
use windows::core::PCWSTR;

use crate::bypass_scan::context::ScanContext;
use crate::bypass_scan::logger::JsonLogger;
use crate::bypass_scan::types::{BypassResult, Confidence, DetectionStatus, EvidenceItem};
use crate::bypass_scan::utils::{
    EventRecord, collect_candidate_files, query_event_records, truncate_text,
};

const EXECUTABLE_EXTS: &[&str] = &["exe", "dll", "sys", "scr", "cpl", "msi", "ocx"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureState {
    Valid,
    NotSigned,
    HashMismatch,
    NotTrusted,
    Unknown(i32),
}

pub fn run(ctx: &ScanContext, logger: &JsonLogger) -> BypassResult {
    let mut result = BypassResult::clean(
        4,
        "bypass04_fake_signature",
        "Fake legitimacy via signature spoofing",
        "No high-confidence signature tampering found.",
    );

    let max_files = match ctx.profile {
        crate::bypass_scan::context::ScanProfile::Quick => 24,
        crate::bypass_scan::context::ScanProfile::Deep => 64,
    };
    let candidates = collect_candidate_files(ctx, EXECUTABLE_EXTS, Some(max_files));
    if candidates.is_empty() {
        result.summary = "No recent executable candidates found in scan roots.".to_string();
        return result;
    }

    let mut hash_mismatch = Vec::new();
    let mut not_trusted = Vec::new();
    let mut not_signed_count = 0usize;
    let mut unknown_count = 0usize;

    let signature_states = candidates
        .par_iter()
        .map(|file| (file.display().to_string(), verify_signature_state(file)))
        .collect::<Vec<_>>();

    for (path, state) in signature_states {
        match state {
            SignatureState::Valid => {}
            SignatureState::NotSigned => {
                // Unsiged alone is not a fake-signature bypass indicator.
                not_signed_count += 1;
            }
            SignatureState::HashMismatch => {
                hash_mismatch.push(path);
            }
            SignatureState::NotTrusted => {
                not_trusted.push(path);
            }
            SignatureState::Unknown(_) => {
                unknown_count += 1;
            }
        }
    }

    let ps_events = query_event_records(
        "Microsoft-Windows-PowerShell/Operational",
        &[4103, 4104],
        180,
    );
    let sec_events = query_event_records("Security", &[4688], 220);
    let sysmon_proc_events = query_event_records("Microsoft-Windows-Sysmon/Operational", &[1], 180);
    let command_hits = collect_signature_tamper_command_hits(&[
        ("PowerShell/Operational", &ps_events),
        ("Security", &sec_events),
        ("Sysmon/Operational", &sysmon_proc_events),
    ]);

    if !hash_mismatch.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::High;
        result.summary =
            "Detected signed binaries with hash mismatch (strong signature tampering indicator)."
                .to_string();
    } else if !not_trusted.is_empty() && !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Medium;
        result.summary =
            "Untrusted signature verification findings correlate with signature-tool command traces."
                .to_string();
    } else if !command_hits.is_empty() {
        result.status = DetectionStatus::Detected;
        result.confidence = Confidence::Low;
        result.summary =
            "Signature modification tooling commands detected in process/script telemetry."
                .to_string();
    }

    if !hash_mismatch.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "WinVerifyTrust".to_string(),
            summary: format!("{} hash-mismatch executable(s)", hash_mismatch.len()),
            details: hash_mismatch.join("; "),
        });
    }

    if !not_trusted.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "WinVerifyTrust".to_string(),
            summary: format!("{} untrusted signed executable(s)", not_trusted.len()),
            details: not_trusted.join("; "),
        });
    }

    result.evidence.push(EvidenceItem {
        source: "WinVerifyTrust scan context".to_string(),
        summary: format!(
            "checked={} valid={} not_signed={} unknown={}",
            candidates.len(),
            candidates.len().saturating_sub(
                not_signed_count + unknown_count + not_trusted.len() + hash_mismatch.len()
            ),
            not_signed_count,
            unknown_count
        ),
        details: "Unsigned binaries are not treated as fake-signature bypass by this detector."
            .to_string(),
    });

    if !command_hits.is_empty() {
        result.evidence.push(EvidenceItem {
            source: "Process/Script command telemetry".to_string(),
            summary: format!("{} signature-tool command hit(s)", command_hits.len()),
            details: command_hits.join("; "),
        });
    }

    if result.status != DetectionStatus::Clean {
        result.recommendations.push(
            "Verify affected files with vendor hashes/cert chain and preserve copies before remediation."
                .to_string(),
        );
    }

    logger.log(
        "bypass04_fake_signature",
        "info",
        "signature scan complete",
        serde_json::json!({
            "candidates": candidates.len(),
            "hash_mismatch": hash_mismatch.len(),
            "not_trusted": not_trusted.len(),
            "not_signed": not_signed_count,
            "unknown": unknown_count,
            "command_hits": command_hits.len(),
            "status": result.status.as_label(),
        }),
    );

    result
}

fn verify_signature_state(path: &Path) -> SignatureState {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND(0),
            &mut action,
            &mut trust_data as *mut _ as *mut core::ffi::c_void,
        )
    };

    map_winverifytrust_status(status)
}

fn map_winverifytrust_status(status: i32) -> SignatureState {
    if status == 0 {
        return SignatureState::Valid;
    }

    if status == TRUST_E_NOSIGNATURE.0
        || status == TRUST_E_SUBJECT_FORM_UNKNOWN.0
        || status == TRUST_E_PROVIDER_UNKNOWN.0
    {
        return SignatureState::NotSigned;
    }

    if status == TRUST_E_BAD_DIGEST.0 {
        return SignatureState::HashMismatch;
    }

    if status == TRUST_E_EXPLICIT_DISTRUST.0
        || status == CERT_E_UNTRUSTEDROOT.0
        || status == CERT_E_UNTRUSTEDTESTROOT.0
        || status == CERT_E_CHAINING.0
        || status == CERT_E_EXPIRED.0
        || status == CERT_E_REVOKED.0
    {
        return SignatureState::NotTrusted;
    }

    SignatureState::Unknown(status)
}

fn collect_signature_tamper_command_hits(event_sets: &[(&str, &[EventRecord])]) -> Vec<String> {
    let mut out = Vec::new();

    for (source, events) in event_sets {
        for event in events.iter() {
            let normalized = format!("{} {}", event.message, event.raw_xml).to_lowercase();
            if !looks_like_signature_tamper_command(&normalized) {
                continue;
            }
            out.push(format!(
                "{} | {} Event {} | {}",
                event.time_created,
                source,
                event.event_id,
                truncate_text(&event.message, 200),
            ));
        }
    }

    out.sort();
    out.dedup();
    out
}

fn looks_like_signature_tamper_command(text: &str) -> bool {
    let normalized = text.to_lowercase();
    (normalized.contains("signtool")
        && (normalized.contains(" sign ") || normalized.contains(" remove ")))
        || normalized.contains("set-authenticodesignature")
        || normalized.contains("sigthief")
        || normalized.contains("osslsigncode")
}

#[cfg(test)]
mod tests {
    use super::{SignatureState, looks_like_signature_tamper_command, map_winverifytrust_status};
    use windows::Win32::Foundation::{
        CERT_E_UNTRUSTEDROOT, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE,
    };

    #[test]
    fn signature_tamper_command_matcher_detects_common_tooling() {
        assert!(looks_like_signature_tamper_command(
            "signtool sign /fd sha256 /a sample.exe"
        ));
        assert!(looks_like_signature_tamper_command(
            "Set-AuthenticodeSignature -FilePath a.exe -Certificate $cert"
        ));
        assert!(!looks_like_signature_tamper_command(
            "Get-AuthenticodeSignature a.exe"
        ));
    }

    #[test]
    fn winverifytrust_status_mapping_prefers_tamper_signals() {
        assert_eq!(
            map_winverifytrust_status(TRUST_E_BAD_DIGEST.0),
            SignatureState::HashMismatch
        );
        assert_eq!(
            map_winverifytrust_status(CERT_E_UNTRUSTEDROOT.0),
            SignatureState::NotTrusted
        );
        assert_eq!(
            map_winverifytrust_status(TRUST_E_NOSIGNATURE.0),
            SignatureState::NotSigned
        );
        assert_eq!(map_winverifytrust_status(0), SignatureState::Valid);
    }
}
