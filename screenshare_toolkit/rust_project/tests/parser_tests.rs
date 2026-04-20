use rust_project::core::parsers::{
    contains_non_ascii, detect_special_extension_fragment, extract_vid_pid, extract_windows_paths,
    normalize_explorer_uri,
};

#[test]
fn extracts_vid_and_pid() {
    let parsed = extract_vid_pid(r"USB\VID_046D&PID_C077\7&2B12");
    assert_eq!(parsed, Some(("046D".to_string(), "C077".to_string())));
}

#[test]
fn normalizes_explorer_file_uri() {
    let path = normalize_explorer_uri("prefix file:///C:/Users/Test/My%20Tool.exe suffix")
        .expect("path should parse");
    assert_eq!(path.to_string_lossy(), r"C:\Users\Test\My Tool.exe");
}

#[test]
fn extracts_windows_paths_from_memory_lines() {
    let paths = extract_windows_paths(
        r#""C:\Temp\tool.exe" something C:\Games\macro.dll and C:\Scripts\run.ps1"#,
    );
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().any(|value| value.ends_with("tool.exe")));
    assert!(paths.iter().any(|value| value.ends_with("macro.dll")));
    assert!(paths.iter().any(|value| value.ends_with("run.ps1")));
}

#[test]
fn detects_special_extension_split() {
    assert!(detect_special_extension_fragment(
        r"C:\Hidden\Path\",
        ".exe"
    ));
    assert!(!detect_special_extension_fragment(
        r"C:\Hidden\Path",
        ".exe"
    ));
}

#[test]
fn detects_non_ascii_lines() {
    assert!(contains_non_ascii("файл"));
    assert!(!contains_non_ascii("plain ascii"));
}
