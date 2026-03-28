use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Clean,
    Detected,
    Warning,
    ManualReview,
    Error,
}

impl DetectionStatus {
    pub fn as_label(self) -> &'static str {
        match self {
            DetectionStatus::Clean => "clean",
            DetectionStatus::Detected => "detected",
            DetectionStatus::Warning => "warning",
            DetectionStatus::ManualReview => "manual_review",
            DetectionStatus::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub source: String,
    pub summary: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResult {
    pub id: u8,
    pub code: String,
    pub name: String,
    pub status: DetectionStatus,
    pub confidence: Confidence,
    pub summary: String,
    pub evidence: Vec<EvidenceItem>,
    pub recommendations: Vec<String>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

impl BypassResult {
    pub fn clean(id: u8, code: &str, name: &str, summary: &str) -> Self {
        Self {
            id,
            code: code.to_string(),
            name: name.to_string(),
            status: DetectionStatus::Clean,
            confidence: Confidence::Low,
            summary: summary.to_string(),
            evidence: Vec::new(),
            recommendations: Vec::new(),
            duration_ms: 0,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u128,
    pub profile: String,
    pub activity_seed_count: usize,
    pub host_name: String,
    pub detector_count: usize,
    pub detected_count: usize,
    pub warning_count: usize,
    pub manual_review_count: usize,
    pub overall_status: String,
    pub results: Vec<BypassResult>,
}
