pub const TOOL_KEYWORDS: &[&str] = &[
    "journaltrace",
    "winprefetchview",
    "prefetchview",
    "systeminformer",
    "processhacker",
    "cleaningdetector",
    "pathparser",
    "lily",
    "forensic",
    "scanner",
];

pub const DOMAIN_KEYWORDS: &[&str] = &[
    "journaltrace",
    "prefetch",
    "forensic",
    "scanner",
    "checker",
    "lily",
    "systeminformer",
];

pub fn contains_tool_keyword(value: &str) -> bool {
    let lower = value.to_lowercase();
    TOOL_KEYWORDS.iter().any(|needle| lower.contains(needle))
}

pub fn contains_domain_keyword(value: &str) -> bool {
    let lower = value.to_lowercase();
    DOMAIN_KEYWORDS.iter().any(|needle| lower.contains(needle))
}
