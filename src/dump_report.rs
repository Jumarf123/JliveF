use anyhow::{Context, Result, anyhow};
use chrono::Local;
use rand::Rng;
use serde::Serialize;
use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Debug, Clone)]
struct RawDump {
    target_java: Option<String>,
    protocol_version: Option<String>,
    session_id: Option<String>,
    dump_profile: Option<String>,
    transport_mode: Option<String>,
    dump_completion: Option<String>,
    target_pid: Option<u32>,
    target_arch: Option<String>,
    agent_flavor: Option<String>,
    class_count: Option<usize>,
    classes_enumerated: Option<usize>,
    classes_dumped: Option<usize>,
    classes_skipped: Option<usize>,
    classes: Vec<RawClass>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DumpInspection {
    pub protocol_version: Option<String>,
    pub session_id: Option<String>,
    pub dump_profile: Option<String>,
    pub transport_mode: Option<String>,
    pub dump_completion: Option<String>,
    pub target_java: Option<String>,
    pub target_pid: Option<u32>,
    pub target_arch: Option<String>,
    pub agent_flavor: Option<String>,
    pub class_count: Option<usize>,
    pub classes_enumerated: Option<usize>,
    pub classes_dumped: usize,
    pub classes_skipped: Option<usize>,
}

#[derive(Debug, Clone, Default)]
struct RawClass {
    name: String,
    package_name: String,
    signature: String,
    generic_signature: String,
    source_file: String,
    code_source_url: String,
    resource_url: String,
    loader: String,
    loader_class: String,
    module_name: String,
    flags: String,
    class_modifiers: String,
    method_count: usize,
    field_count: usize,
    methods: Vec<MemberRecord>,
    fields: Vec<MemberRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct MemberRecord {
    modifiers: String,
    name: String,
    signature: String,
    generic_signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ClassCategory {
    Suspect,
    Lambda,
    Unknown,
    Normal,
}

impl ClassCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Suspect => "suspect",
            Self::Lambda => "lambda",
            Self::Unknown => "unknown",
            Self::Normal => "normal",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Suspect => "Suspect",
            Self::Lambda => "Lambda",
            Self::Unknown => "Unknown",
            Self::Normal => "Normal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OriginKind {
    Jar,
    Directory,
    File,
    Unknown,
}

impl OriginKind {
    fn label(self) -> &'static str {
        match self {
            Self::Jar => "jar",
            Self::Directory => "directory",
            Self::File => "file",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct OriginInfo {
    path: String,
    kind: OriginKind,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReportClass {
    category: String,
    category_title: String,
    name: String,
    package_name: String,
    signature: String,
    generic_signature: String,
    source_file: String,
    source_reference: String,
    code_source_url: String,
    resource_url: String,
    origin_path: String,
    origin_kind: String,
    origin_source: String,
    loader: String,
    loader_class: String,
    module_name: String,
    flags: Vec<String>,
    class_modifiers: String,
    method_count: usize,
    field_count: usize,
    methods: Vec<MemberRecord>,
    fields: Vec<MemberRecord>,
    score: i32,
    reasons: Vec<String>,
    has_non_english: bool,
    standard_package: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProcessedDump {
    pub report_path: PathBuf,
    pub html_path: PathBuf,
    pub index_path: PathBuf,
    pub dump_profile: Option<String>,
    pub dump_completion: Option<String>,
    pub total_classes: usize,
    pub classes_enumerated: Option<usize>,
    pub classes_skipped: Option<usize>,
    pub suspect_count: usize,
    pub lambda_count: usize,
    pub unknown_count: usize,
    pub normal_count: usize,
}

pub fn inspect_dump_file(path: &Path) -> Result<DumpInspection> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading dump file {}", path.display()))?;
    let parsed = parse_dump(&raw)?;
    Ok(DumpInspection {
        protocol_version: parsed.protocol_version,
        session_id: parsed.session_id,
        dump_profile: parsed.dump_profile,
        transport_mode: parsed.transport_mode,
        dump_completion: parsed.dump_completion,
        target_java: parsed.target_java,
        target_pid: parsed.target_pid,
        target_arch: parsed.target_arch,
        agent_flavor: parsed.agent_flavor,
        class_count: parsed.class_count,
        classes_enumerated: parsed.classes_enumerated,
        classes_dumped: parsed.classes_dumped.unwrap_or(parsed.classes.len()),
        classes_skipped: parsed.classes_skipped,
    })
}

pub fn process_dump_file(path: &Path) -> Result<ProcessedDump> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading dump file {}", path.display()))?;
    let parsed = parse_dump(&raw)?;
    let mut classes: Vec<ReportClass> = parsed
        .classes
        .iter()
        .cloned()
        .map(|class| build_report_class_for_dump(class, parsed.dump_profile.as_deref()))
        .collect::<Result<Vec<_>>>()?;

    classes.sort_by(compare_classes);

    let base_output_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let output_dir = create_report_dir(base_output_dir)?;

    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("classes");
    let report_path = output_dir.join(format!("{stem}.txt"));
    let html_path = output_dir.join(format!("{stem}.html"));
    let index_path = output_dir.join("Index.html");

    let text = render_text_report(&parsed, &classes);
    let html = render_html_report(&parsed, &classes)?;

    write_atomic(&report_path, text.as_bytes())?;
    write_atomic(&html_path, html.as_bytes())?;
    write_atomic(&index_path, html.as_bytes())?;

    let suspect_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Suspect.as_str())
        .count();
    let lambda_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Lambda.as_str())
        .count();
    let unknown_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Unknown.as_str())
        .count();
    let normal_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Normal.as_str())
        .count();

    Ok(ProcessedDump {
        report_path,
        html_path,
        index_path,
        dump_profile: parsed.dump_profile.clone(),
        dump_completion: parsed.dump_completion.clone(),
        total_classes: classes.len(),
        classes_enumerated: parsed.classes_enumerated.or(parsed.class_count),
        classes_skipped: parsed.classes_skipped,
        suspect_count,
        lambda_count,
        unknown_count,
        normal_count,
    })
}

pub fn write_simple_dump_file(path: &Path, report_path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading dump file {}", path.display()))?;
    let parsed = parse_dump(&raw)?;
    let text = render_simple_report(&parsed);
    write_atomic(report_path, text.as_bytes())
}

fn parse_dump(input: &str) -> Result<RawDump> {
    let mut dump = RawDump {
        target_java: None,
        protocol_version: None,
        session_id: None,
        dump_profile: None,
        transport_mode: None,
        dump_completion: None,
        target_pid: None,
        target_arch: None,
        agent_flavor: None,
        class_count: None,
        classes_enumerated: None,
        classes_dumped: None,
        classes_skipped: None,
        classes: Vec::new(),
    };
    let mut current: Option<RawClass> = None;

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed == "JLIVEF_DUMP_V2"
            || trimmed == "JLIVEF_DUMP_V3"
            || trimmed == "JLIVEF_DUMP_V4"
        {
            continue;
        }

        if trimmed == "@@CLASS" {
            if let Some(previous) = current.take() {
                dump.classes.push(previous);
            }
            current = Some(RawClass::default());
            continue;
        }

        if trimmed == "@@END" {
            if let Some(previous) = current.take() {
                dump.classes.push(previous);
            }
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("ProtocolVersion:") {
            dump.protocol_version = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("SessionId:") {
            dump.session_id = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("DumpProfile:") {
            dump.dump_profile = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("TransportMode:") {
            dump.transport_mode = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("DumpCompletion:") {
            dump.dump_completion = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("TargetJava:") {
            dump.target_java = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("DetectedJavaMajor:") {
            dump.target_java = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("TargetPid:") {
            dump.target_pid = clean_value(value).parse::<u32>().ok();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("TargetArch:") {
            dump.target_arch = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("AgentFlavor:") {
            dump.agent_flavor = Some(clean_value(value));
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("ClassCount:") {
            dump.class_count = clean_value(value).parse::<usize>().ok();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("ClassesEnumerated:") {
            dump.classes_enumerated = clean_value(value).parse::<usize>().ok();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("ClassesDumped:") {
            dump.classes_dumped = clean_value(value).parse::<usize>().ok();
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("ClassesSkipped:") {
            dump.classes_skipped = clean_value(value).parse::<usize>().ok();
            continue;
        }

        let Some(class) = current.as_mut() else {
            continue;
        };

        if let Some(value) = trimmed.strip_prefix("Name:") {
            class.name = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("Package:") {
            class.package_name = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("Signature:") {
            class.signature = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("GenericSignature:") {
            class.generic_signature = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("SourceFile:") {
            class.source_file = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("CodeSourceUrl:") {
            class.code_source_url = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("ResourceUrl:") {
            class.resource_url = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("Loader:") {
            class.loader = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("LoaderClass:") {
            class.loader_class = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("Module:") {
            class.module_name = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("Flags:") {
            class.flags = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("ClassModifiers:") {
            class.class_modifiers = clean_value(value);
        } else if let Some(value) = trimmed.strip_prefix("MethodCount:") {
            class.method_count = clean_value(value).parse::<usize>().unwrap_or(0);
        } else if let Some(value) = trimmed.strip_prefix("FieldCount:") {
            class.field_count = clean_value(value).parse::<usize>().unwrap_or(0);
        } else if let Some(value) = trimmed.strip_prefix("Method:") {
            class.methods.push(parse_method_record(value));
        } else if let Some(value) = trimmed.strip_prefix("Field:") {
            class.fields.push(parse_field_record(value));
        }
    }

    if let Some(previous) = current.take() {
        dump.classes.push(previous);
    }

    let effective_dumped = dump.classes_dumped.unwrap_or(dump.classes.len());
    if dump.classes.is_empty() && effective_dumped == 0 {
        return Ok(dump);
    }

    if dump.classes.is_empty() {
        return Err(anyhow!("dump file does not contain any classes"));
    }

    Ok(dump)
}

fn clean_value(value: &str) -> String {
    let cleaned = value.trim();
    if cleaned.eq_ignore_ascii_case("unknown") {
        String::new()
    } else {
        cleaned.to_string()
    }
}

fn parse_method_record(value: &str) -> MemberRecord {
    let mut record = MemberRecord {
        modifiers: String::new(),
        name: String::new(),
        signature: String::new(),
        generic_signature: String::new(),
    };

    if !value.contains('|') {
        let (name, signature) = split_member_signature(value.trim());
        record.name = name;
        record.signature = signature;
        return record;
    }

    let parts: Vec<&str> = value.split('|').map(str::trim).collect();
    if let Some(modifiers) = parts.first() {
        record.modifiers = clean_value(modifiers);
    }
    if let Some(name_and_sig) = parts.get(1) {
        let (name, signature) = split_member_signature(name_and_sig);
        record.name = name;
        record.signature = signature;
    }
    if let Some(generic) = parts.get(2) {
        record.generic_signature = clean_value(generic.trim_start_matches("Generic=").trim());
    }
    record
}

fn parse_field_record(value: &str) -> MemberRecord {
    let mut record = MemberRecord {
        modifiers: String::new(),
        name: String::new(),
        signature: String::new(),
        generic_signature: String::new(),
    };

    if !value.contains('|') {
        let trimmed = value.trim();
        if let Some((name, signature)) = trimmed.split_once(':') {
            record.name = clean_value(name);
            record.signature = clean_value(signature);
        } else {
            record.name = clean_value(trimmed);
        }
        return record;
    }

    let parts: Vec<&str> = value.split('|').map(str::trim).collect();
    if let Some(modifiers) = parts.first() {
        record.modifiers = clean_value(modifiers);
    }
    if let Some(name) = parts.get(1) {
        record.name = clean_value(name);
    }
    if let Some(signature) = parts.get(2) {
        record.signature = clean_value(signature.trim_start_matches("Signature=").trim());
    }
    if let Some(generic) = parts.get(3) {
        record.generic_signature = clean_value(generic.trim_start_matches("Generic=").trim());
    }
    record
}

fn split_member_signature(value: &str) -> (String, String) {
    if let Some(pos) = value.find('(') {
        let name = value[..pos].trim().to_string();
        let signature = value[pos..].trim().to_string();
        (name, signature)
    } else {
        (value.trim().to_string(), String::new())
    }
}

#[allow(dead_code)]
fn build_report_class(raw: RawClass) -> Result<ReportClass> {
    build_report_class_for_dump(raw, None)
}

fn build_report_class_for_dump(raw: RawClass, dump_profile: Option<&str>) -> Result<ReportClass> {
    let core_profile = dump_profile.is_some_and(|value| value.eq_ignore_ascii_case("core"));
    let standard_package = is_standard_package(&raw.name);
    let lambda_class = is_lambda_class(&raw.name);
    let array_class = raw.flags.contains("array") || raw.name.starts_with('[');
    let primitive_class = raw.flags.contains("primitive");
    let has_non_english = has_non_english_letters(&raw.name);
    let origin = derive_origin(&raw)?;
    let has_any_provenance = !raw.code_source_url.is_empty() || !raw.resource_url.is_empty();
    let trusted_runtime = is_trusted_runtime_class(&raw, &origin, standard_package);
    let missing_provenance = !core_profile
        && origin.kind == OriginKind::Unknown
        && !has_any_provenance
        && !trusted_runtime;
    let weak_provenance = !core_profile
        && origin.kind == OriginKind::Unknown
        && has_any_provenance
        && !trusted_runtime;
    let source_reference = derive_source_reference(&raw, &origin);
    let has_source_reference = !source_reference.trim().is_empty();
    let source_reference_missing_signal = !core_profile && !has_source_reference;
    let explicit_name_score = explicit_identifier_score(simple_class_name(&raw.name));
    let name_score = class_name_signal_score(&raw.name);
    let member_score = member_signal_score(&raw.methods, &raw.fields);
    let trusted_context = standard_package || trusted_runtime;

    let mut reasons = Vec::new();
    let mut score = 0;

    if has_non_english {
        score += 140;
        reasons.push("non-English letters or control characters in class name".to_string());
    }
    if name_score >= 55 {
        score += name_score;
        reasons.push(format!("obfuscated-looking class name ({name_score})"));
    }
    if member_score >= 24 {
        score += member_score;
        reasons.push(format!("obfuscated-looking member names ({member_score})"));
    }
    if missing_provenance {
        score += if standard_package { 18 } else { 30 };
        reasons.push("no CodeSource URL, Resource URL or jar/path could be resolved".to_string());
    } else if weak_provenance {
        score += if standard_package { 4 } else { 18 };
        reasons.push("origin path could not be resolved".to_string());
    }
    if source_reference_missing_signal
        && !trusted_context
        && !lambda_class
        && !array_class
        && !primitive_class
    {
        score += 4;
        reasons.push("source file or class entry is missing".to_string());
    }
    if raw.flags.contains("synthetic") && !lambda_class && !trusted_context {
        score += 6;
        reasons.push("class is synthetic".to_string());
    }
    if raw.flags.contains("anonymous") && !lambda_class && !trusted_context {
        score += 6;
        reasons.push("class is anonymous".to_string());
    }

    let category = if lambda_class {
        ClassCategory::Lambda
    } else if array_class || primitive_class {
        if missing_provenance {
            ClassCategory::Unknown
        } else {
            ClassCategory::Normal
        }
    } else if has_non_english {
        ClassCategory::Suspect
    } else if !trusted_context
        && (explicit_name_score >= 120 || name_score >= 90 || member_score >= 96 || score >= 110)
    {
        ClassCategory::Suspect
    } else if missing_provenance {
        ClassCategory::Unknown
    } else if weak_provenance
        || (!standard_package
            && (explicit_name_score >= 90
                || name_score >= 48
                || member_score >= 42
                || source_reference_missing_signal))
    {
        ClassCategory::Unknown
    } else {
        ClassCategory::Normal
    };

    Ok(ReportClass {
        category: category.as_str().to_string(),
        category_title: category.title().to_string(),
        name: raw.name,
        package_name: raw.package_name,
        signature: raw.signature,
        generic_signature: raw.generic_signature,
        source_file: raw.source_file,
        source_reference,
        code_source_url: raw.code_source_url,
        resource_url: raw.resource_url,
        origin_path: origin.path,
        origin_kind: origin.kind.label().to_string(),
        origin_source: origin.source,
        loader: raw.loader,
        loader_class: raw.loader_class,
        module_name: raw.module_name,
        flags: split_csv(&raw.flags),
        class_modifiers: raw.class_modifiers,
        method_count: raw.method_count.max(raw.methods.len()),
        field_count: raw.field_count.max(raw.fields.len()),
        methods: raw.methods,
        fields: raw.fields,
        score,
        reasons,
        has_non_english,
        standard_package,
    })
}

fn derive_origin(raw: &RawClass) -> Result<OriginInfo> {
    let class_resource = class_resource_path(&raw.name);
    if let Some(info) = parse_origin_candidate(&raw.code_source_url, &class_resource)? {
        return Ok(OriginInfo {
            source: "CodeSource".to_string(),
            ..info
        });
    }
    if let Some(info) = parse_origin_candidate(&raw.resource_url, &class_resource)? {
        return Ok(OriginInfo {
            source: "Resource".to_string(),
            ..info
        });
    }
    Ok(OriginInfo {
        path: String::new(),
        kind: OriginKind::Unknown,
        source: String::new(),
    })
}

fn parse_origin_candidate(value: &str, class_resource: &str) -> Result<Option<OriginInfo>> {
    let mut raw = value.trim();
    if raw.is_empty() {
        return Ok(None);
    }

    let mut from_jar_wrapper = false;
    if let Some(stripped) = raw.strip_prefix("jar:") {
        raw = stripped;
        from_jar_wrapper = true;
    }

    let mut split_at_bang = false;
    if let Some((before, _)) = raw.split_once("!/") {
        raw = before;
        split_at_bang = true;
    } else if let Some((before, _)) = raw.split_once("!\\") {
        raw = before;
        split_at_bang = true;
    }

    let mut path = if raw.starts_with("file:") {
        match Url::parse(raw) {
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map(|path| path.to_string_lossy().to_string())
                .map_err(|_| anyhow!("failed to convert file URL {raw}"))?,
            _ => raw.trim_start_matches("file:").replace('/', "\\"),
        }
    } else {
        raw.replace('/', "\\")
    };

    if path.starts_with('\\')
        && path.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
        && path.as_bytes().get(2) == Some(&b':')
    {
        path.remove(0);
    }

    let class_resource_win = class_resource.replace('/', "\\");
    let path_lower = path.to_ascii_lowercase();
    let class_resource_lower = class_resource_win.to_ascii_lowercase();
    if path_lower.ends_with(&class_resource_lower) {
        let new_len = path.len().saturating_sub(class_resource_win.len());
        path.truncate(new_len);
        while path.ends_with('\\') || path.ends_with('/') {
            path.pop();
        }
    }

    let kind = if from_jar_wrapper || split_at_bang || has_archive_extension(&path) {
        OriginKind::Jar
    } else if path.ends_with(".class") {
        OriginKind::File
    } else if !path.is_empty() {
        OriginKind::Directory
    } else {
        OriginKind::Unknown
    };

    if path.is_empty() {
        Ok(None)
    } else {
        Ok(Some(OriginInfo {
            path,
            kind,
            source: String::new(),
        }))
    }
}

fn has_archive_extension(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.ends_with(".jar") || lower.ends_with(".zip")
}

fn class_resource_path(class_name: &str) -> String {
    format!("{}.class", class_name.replace('.', "/"))
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty() && *item != "none")
        .map(ToString::to_string)
        .collect()
}

fn derive_source_reference(raw: &RawClass, origin: &OriginInfo) -> String {
    if !raw.source_file.trim().is_empty() {
        return raw.source_file.clone();
    }

    if let Some(entry) = resource_entry_from_url(&raw.resource_url) {
        if !origin.path.is_empty() && origin.kind == OriginKind::Jar {
            return format!("{}!/{}", origin.path, entry);
        }
        return entry;
    }

    let class_resource = class_resource_path(&raw.name);
    match origin.kind {
        OriginKind::Jar if !origin.path.is_empty() => {
            format!("{}!/{}", origin.path, class_resource)
        }
        OriginKind::Directory if !origin.path.is_empty() => {
            format!(
                "{}\\{}",
                origin.path.trim_end_matches(['\\', '/']),
                class_resource.replace('/', "\\")
            )
        }
        OriginKind::File if !origin.path.is_empty() => origin.path.clone(),
        _ => String::new(),
    }
}

fn is_trusted_runtime_class(raw: &RawClass, origin: &OriginInfo, standard_package: bool) -> bool {
    if !standard_package {
        return false;
    }

    let loader = raw.loader.to_ascii_lowercase();
    let loader_class = raw.loader_class.to_ascii_lowercase();
    let module = raw.module_name.to_ascii_lowercase();
    let resource = raw.resource_url.to_ascii_lowercase();

    loader == "bootstrap"
        || loader_class == "bootstrap"
        || resource.starts_with("jrt:/")
        || origin.path.to_ascii_lowercase().starts_with("jrt:")
        || module.starts_with("java.")
        || module.starts_with("jdk.")
        || module == "java.base"
        || module == "java.desktop"
        || module == "java.xml"
}

fn resource_entry_from_url(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    trimmed
        .split_once("!/")
        .map(|(_, entry)| entry.to_string())
        .or_else(|| {
            trimmed
                .split_once("!\\")
                .map(|(_, entry)| entry.replace('\\', "/"))
        })
}

fn is_lambda_class(name: &str) -> bool {
    name.contains("$$Lambda$")
        || name.contains("$Lambda")
        || name.contains("LambdaForm$")
        || name.contains("lambda$")
}

fn has_non_english_letters(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || (ch.is_alphabetic() && !ch.is_ascii()))
}

fn is_standard_package(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "java.",
        "javax.",
        "jdk.",
        "sun.",
        "com.sun.",
        "org.objectweb.",
        "org.w3c.",
        "org.xml.",
        "org.slf4j.",
        "org.apache.",
        "org.lwjgl.",
        "org.joml.",
        "com.google.",
        "com.mojang.",
        "net.fabricmc.",
        "org.spongepowered.",
        "it.unimi.",
        "kotlin.",
        "kotlinx.",
        "scala.",
        "groovy.",
        "net.bytebuddy.",
        "org.jetbrains.",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn class_name_signal_score(name: &str) -> i32 {
    let simple = simple_class_name(name);
    let tokens = split_tokens(simple);
    explicit_identifier_score(simple).max(token_group_score(&tokens, 1))
}

fn simple_class_name(name: &str) -> &str {
    name.rsplit(['.', '/', '\\']).next().unwrap_or(name)
}

fn member_signal_score(methods: &[MemberRecord], fields: &[MemberRecord]) -> i32 {
    let mut tokens = Vec::new();
    for method in methods.iter().take(80) {
        if should_ignore_member_for_obf_score(&method.name, &method.modifiers) {
            continue;
        }
        tokens.push(method.name.clone());
    }
    for field in fields.iter().take(80) {
        if should_ignore_member_for_obf_score(&field.name, &field.modifiers) {
            continue;
        }
        tokens.push(field.name.clone());
    }

    let mut scored: Vec<i32> = tokens
        .iter()
        .flat_map(|token| split_tokens(token))
        .map(|token| token_score(&token))
        .filter(|score| *score > 0)
        .collect();
    scored.sort_by_key(|score| Reverse(*score));
    scored.into_iter().take(8).map(|score| score / 3).sum()
}

fn should_ignore_member_for_obf_score(name: &str, modifiers: &str) -> bool {
    let lowered_name = name.trim();
    let lowered_modifiers = modifiers.to_ascii_lowercase();

    lowered_name == "<init>"
        || lowered_name == "<clinit>"
        || lowered_name.starts_with("lambda$")
        || lowered_name.starts_with("access$")
        || lowered_name.starts_with("this$")
        || lowered_name.starts_with("val$")
        || lowered_name.starts_with("arg$")
        || lowered_name.starts_with("$SwitchMap$")
        || lowered_modifiers.contains("synthetic")
}

fn token_group_score(tokens: &[String], class_weight: i32) -> i32 {
    let mut scored: Vec<i32> = tokens
        .iter()
        .map(|token| token_score(token))
        .filter(|score| *score > 0)
        .collect();
    scored.sort_by_key(|score| Reverse(*score));

    let sum: i32 = scored.iter().take(6).sum();
    let max = scored.first().copied().unwrap_or(0);
    (max * class_weight).max(sum / 2)
}

fn split_tokens(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || (!ch.is_ascii() && ch.is_alphabetic()) {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn token_score(token: &str) -> i32 {
    if token.is_empty() {
        return 0;
    }

    let length = token.chars().count();
    if length <= 6 && token.chars().all(|ch| ch.is_ascii_uppercase()) {
        return 0;
    }

    if token.chars().any(|ch| ch.is_control()) {
        return 100;
    }

    if token.chars().any(|ch| ch.is_alphabetic() && !ch.is_ascii()) {
        return 100;
    }

    let lower = token.to_ascii_lowercase();
    if is_known_token(&lower) || lower == "lambda" {
        return 0;
    }
    if lower.chars().all(|ch| ch.is_ascii_digit()) {
        return 0;
    }

    let digit_count = lower.chars().filter(|ch| ch.is_ascii_digit()).count();
    let alpha_count = lower.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    let uppercase_count = token.chars().filter(|ch| ch.is_ascii_uppercase()).count();
    let vowel_count = lower
        .chars()
        .filter(|ch| matches!(ch, 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
        .count();

    if looks_like_ordinal_token(&lower) {
        return 0;
    }
    if alpha_count >= 3 && digit_count > 0 && uppercase_count > 0 {
        return 0;
    }
    if digit_count == 0 && alpha_count >= 5 && vowel_count >= 1 {
        return 0;
    }
    if length <= 3 {
        return 0;
    }
    if length >= 8 && lower.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return 120;
    }
    if alpha_count >= 5 && vowel_count == 0 && uppercase_count == 0 && length <= 8 {
        return 58;
    }
    if alpha_count >= 7 && vowel_count * 5 < alpha_count && uppercase_count == 0 && length <= 10 {
        return 34;
    }
    if length >= 6 && digit_count * 10 >= length * 5 && uppercase_count == 0 {
        return 48;
    }

    0
}

fn explicit_identifier_score(value: &str) -> i32 {
    let lower = value.to_ascii_lowercase();
    let mut score = 0;

    if contains_prefixed_number(&lower, "class_")
        || contains_prefixed_number(&lower, "method_")
        || contains_prefixed_number(&lower, "field_")
        || contains_prefixed_number(&lower, "comp_")
    {
        score = score.max(130);
    }

    for segment in split_identifier_segments(&lower) {
        if segment.len() >= 8 && segment.chars().all(|ch| ch.is_ascii_hexdigit()) {
            score = score.max(150);
        } else {
            let digit_count = segment.chars().filter(|ch| ch.is_ascii_digit()).count();
            let alpha_count = segment
                .chars()
                .filter(|ch| ch.is_ascii_alphabetic())
                .count();
            let vowel_count = segment
                .chars()
                .filter(|ch| matches!(ch, 'a' | 'e' | 'i' | 'o' | 'u' | 'y'))
                .count();

            if segment.len() >= 10 && digit_count >= 3 && digit_count * 10 >= segment.len() * 4 {
                score = score.max(110);
            }
            if alpha_count >= 6 && vowel_count == 0 && segment.len() <= 10 {
                score = score.max(74);
            }
        }
    }

    score
}

fn contains_prefixed_number(value: &str, prefix: &str) -> bool {
    let mut start = 0usize;
    while let Some(offset) = value[start..].find(prefix) {
        let idx = start + offset + prefix.len();
        let digit_count = value[idx..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .count();
        if digit_count >= 2 {
            return true;
        }
        start += offset + prefix.len();
    }
    false
}

fn split_identifier_segments(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

fn looks_like_ordinal_token(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }

    let rest: String = chars.collect();
    if rest.is_empty() || rest.len() > 2 {
        return false;
    }

    rest.chars().all(|ch| ch.is_ascii_digit())
}

fn is_known_token(token: &str) -> bool {
    matches!(
        token,
        "com"
            | "net"
            | "org"
            | "io"
            | "app"
            | "api"
            | "core"
            | "util"
            | "utils"
            | "common"
            | "impl"
            | "internal"
            | "interface"
            | "loader"
            | "launch"
            | "launcher"
            | "client"
            | "server"
            | "module"
            | "mod"
            | "mods"
            | "main"
            | "config"
            | "event"
            | "events"
            | "handler"
            | "helper"
            | "manager"
            | "service"
            | "factory"
            | "callback"
            | "invoke"
            | "ffi"
            | "cif"
            | "entry"
            | "entries"
            | "minecraft"
            | "mojang"
            | "fabric"
            | "forge"
            | "quilt"
            | "mixin"
            | "lwjgl"
            | "glfw"
            | "kotlin"
            | "scala"
            | "java"
            | "javax"
            | "jdk"
            | "sun"
            | "class"
            | "method"
            | "field"
            | "value"
            | "name"
            | "string"
            | "object"
            | "list"
            | "map"
            | "set"
            | "data"
            | "info"
            | "type"
            | "test"
            | "gui"
            | "screen"
            | "item"
            | "block"
            | "world"
    )
}

fn compare_classes(left: &ReportClass, right: &ReportClass) -> std::cmp::Ordering {
    let left_category = match left.category.as_str() {
        "suspect" => 0,
        "lambda" => 1,
        "unknown" => 2,
        _ => 3,
    };
    let right_category = match right.category.as_str() {
        "suspect" => 0,
        "lambda" => 1,
        "unknown" => 2,
        _ => 3,
    };

    left_category
        .cmp(&right_category)
        .then_with(|| right.score.cmp(&left.score))
        .then_with(|| {
            left.origin_path
                .is_empty()
                .cmp(&right.origin_path.is_empty())
        })
        .then_with(|| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
        })
}

fn render_text_report(parsed: &RawDump, classes: &[ReportClass]) -> String {
    let mut out = String::new();
    let generated = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let target_java = parsed
        .target_java
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let total_classes = classes.len();
    let suspect_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Suspect.as_str())
        .count();
    let lambda_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Lambda.as_str())
        .count();
    let unknown_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Unknown.as_str())
        .count();
    let normal_count = classes
        .iter()
        .filter(|class| class.category == ClassCategory::Normal.as_str())
        .count();
    let enumerated = parsed.classes_enumerated.or(parsed.class_count);
    let dumped = parsed.classes_dumped.unwrap_or(total_classes);
    let skipped = parsed
        .classes_skipped
        .or_else(|| enumerated.map(|value| value.saturating_sub(dumped)));

    out.push_str("Classes Report\n");
    out.push_str("==============\n");
    out.push_str(&format!("Generated: {generated}\n"));
    out.push_str(&format!("Target Java: {target_java}\n"));
    if let Some(protocol_version) = parsed.protocol_version.as_deref() {
        out.push_str(&format!("ProtocolVersion: {protocol_version}\n"));
    }
    if let Some(session_id) = parsed.session_id.as_deref() {
        out.push_str(&format!("SessionId: {session_id}\n"));
    }
    if let Some(profile) = parsed.dump_profile.as_deref() {
        out.push_str(&format!("Dump Profile: {profile}\n"));
    }
    if let Some(transport_mode) = parsed.transport_mode.as_deref() {
        out.push_str(&format!("Transport Mode: {transport_mode}\n"));
    }
    if let Some(completion) = parsed.dump_completion.as_deref() {
        out.push_str(&format!("Dump Completion: {completion}\n"));
    }
    if let Some(target_pid) = parsed.target_pid {
        out.push_str(&format!("Target PID: {target_pid}\n"));
    }
    if let Some(target_arch) = parsed.target_arch.as_deref() {
        out.push_str(&format!("Target Arch: {target_arch}\n"));
    }
    if let Some(agent_flavor) = parsed.agent_flavor.as_deref() {
        out.push_str(&format!("Agent Flavor: {agent_flavor}\n"));
    }
    if let Some(class_count) = enumerated {
        out.push_str(&format!("JVMTI ClassCount: {class_count}\n"));
    }
    out.push_str(&format!("Processed classes: {total_classes}\n"));
    out.push_str(&format!("Classes dumped: {dumped}\n"));
    if let Some(skipped) = skipped {
        out.push_str(&format!("Classes skipped: {skipped}\n"));
    }
    out.push_str(&format!(
        "Completeness: enumerated={}, dumped={}, skipped={}\n",
        enumerated
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        dumped,
        skipped
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    ));
    if parsed
        .dump_profile
        .as_deref()
        .is_some_and(|profile| profile.eq_ignore_ascii_case("core"))
    {
        out.push_str("Provenance: not collected in core mode\n");
    }
    out.push_str(&format!(
        "Annotations: suspect={suspect_count}, lambda={lambda_count}, unknown={unknown_count}, normal={normal_count}\n\n"
    ));

    for category in [
        ClassCategory::Suspect,
        ClassCategory::Lambda,
        ClassCategory::Unknown,
        ClassCategory::Normal,
    ] {
        let section: Vec<&ReportClass> = classes
            .iter()
            .filter(|class| class.category == category.as_str())
            .collect();
        out.push_str(&format!("\n{} [{}]\n", category.title(), section.len()));
        out.push_str(&format!(
            "{}\n",
            "=".repeat(category.title().len() + section.len().to_string().len() + 3)
        ));

        if section.is_empty() {
            out.push_str("No classes.\n\n");
            continue;
        }

        for (index, class) in section.iter().enumerate() {
            out.push_str(&format!("\n{}. {}\n", index + 1, class.name));
            out.push_str(&format!(
                "   {}\n",
                "-".repeat(class.name.len().min(96) + 3)
            ));
            out.push_str(&format!("   Category: {}\n", class.category_title));
            out.push_str(&format!("   Risk Score: {}\n", class.score));
            if !class.reasons.is_empty() {
                out.push_str(&format!("   Reasons: {}\n", class.reasons.join("; ")));
            }
            out.push_str("   Origin\n");
            out.push_str(&format!(
                "     Path: {}\n",
                display_or_unknown(&class.origin_path)
            ));
            out.push_str(&format!(
                "     Type: {}\n",
                display_or_unknown(&class.origin_kind)
            ));
            out.push_str(&format!(
                "     Source: {}\n",
                display_or_unknown(&class.origin_source)
            ));
            out.push_str(&format!(
                "     CodeSource URL: {}\n",
                display_or_unknown(&class.code_source_url)
            ));
            out.push_str(&format!(
                "     Resource URL: {}\n",
                display_or_unknown(&class.resource_url)
            ));
            out.push_str("   Metadata\n");
            out.push_str(&format!(
                "     Package: {}\n",
                display_or_unknown(&class.package_name)
            ));
            out.push_str(&format!(
                "     Module: {}\n",
                display_or_unknown(&class.module_name)
            ));
            out.push_str(&format!(
                "     Loader: {}\n",
                display_or_unknown(&class.loader)
            ));
            out.push_str(&format!(
                "     Loader Class: {}\n",
                display_or_unknown(&class.loader_class)
            ));
            out.push_str(&format!(
                "     Source / Entry: {}\n",
                display_or_unknown(&class.source_reference)
            ));
            out.push_str(&format!(
                "     Class Modifiers: {}\n",
                display_or_unknown(&class.class_modifiers)
            ));
            out.push_str(&format!(
                "     Flags: {}\n",
                if class.flags.is_empty() {
                    "Unknown".to_string()
                } else {
                    class.flags.join(", ")
                }
            ));
            out.push_str(&format!(
                "     Signature: {}\n",
                display_or_unknown(&class.signature)
            ));
            out.push_str(&format!(
                "     Generic Signature: {}\n",
                display_or_unknown(&class.generic_signature)
            ));
            out.push_str(&format!("   Methods [{}]:\n", class.method_count));
            if class.methods.is_empty() {
                out.push_str("     - none\n");
            } else {
                for method in &class.methods {
                    out.push_str(&format!(
                        "     - {} {} {}\n",
                        display_or_unknown(&method.modifiers),
                        method.name,
                        display_or_unknown(&method.signature)
                    ));
                }
            }
            out.push_str(&format!("   Fields [{}]:\n", class.field_count));
            if class.fields.is_empty() {
                out.push_str("     - none\n");
            } else {
                for field in &class.fields {
                    out.push_str(&format!(
                        "     - {} {} {}\n",
                        display_or_unknown(&field.modifiers),
                        field.name,
                        display_or_unknown(&field.signature)
                    ));
                }
            }
            out.push('\n');
        }
    }

    out
}

fn render_simple_report(parsed: &RawDump) -> String {
    let mut classes = parsed.classes.clone();
    classes.sort_by(|left, right| left.name.cmp(&right.name));

    let mut out = String::new();
    out.push_str("JLIVEF SIMPLE DUMPER\n");
    if let Some(pid) = parsed.target_pid {
        out.push_str(&format!("Target PID: {pid}\n"));
    }
    if let Some(profile) = &parsed.dump_profile {
        out.push_str(&format!("Source Profile: {profile}\n"));
    }
    if let Some(java) = &parsed.target_java {
        out.push_str(&format!("Java: {java}\n"));
    }
    out.push_str(&format!("Classes: {}\n\n", classes.len()));

    for class in &classes {
        out.push_str(&format!("Class: {}\n", class.name));
        out.push_str("  Methods:\n");
        if class.methods.is_empty() {
            out.push_str("    <none>\n");
        } else {
            for method in &class.methods {
                out.push_str(&format!(
                    "    {}{}{}\n",
                    method.name,
                    method.signature,
                    if method.generic_signature.is_empty() || method.generic_signature == "-" {
                        String::new()
                    } else {
                        format!(" | Generic={}", method.generic_signature)
                    }
                ));
            }
        }

        out.push_str("  Fields:\n");
        if class.fields.is_empty() {
            out.push_str("    <none>\n");
        } else {
            for field in &class.fields {
                out.push_str(&format!(
                    "    {} : {}{}\n",
                    field.name,
                    field.signature,
                    if field.generic_signature.is_empty() || field.generic_signature == "-" {
                        String::new()
                    } else {
                        format!(" | Generic={}", field.generic_signature)
                    }
                ));
            }
        }
        out.push('\n');
    }

    out
}

fn display_or_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "Unknown".to_string()
    } else {
        value.to_string()
    }
}

fn render_html_report(parsed: &RawDump, classes: &[ReportClass]) -> Result<String> {
    #[derive(Serialize)]
    struct HtmlPayload<'a> {
        generated_at: String,
        target_java: String,
        protocol_version: Option<String>,
        session_id: Option<String>,
        dump_profile: Option<String>,
        transport_mode: Option<String>,
        dump_completion: Option<String>,
        target_pid: Option<u32>,
        target_arch: Option<String>,
        agent_flavor: Option<String>,
        classes_enumerated: Option<usize>,
        classes_dumped: usize,
        classes_skipped: Option<usize>,
        total_classes: usize,
        suspect_count: usize,
        lambda_count: usize,
        unknown_count: usize,
        normal_count: usize,
        classes: &'a [ReportClass],
    }

    let payload = HtmlPayload {
        generated_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        target_java: parsed
            .target_java
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        protocol_version: parsed.protocol_version.clone(),
        session_id: parsed.session_id.clone(),
        dump_profile: parsed.dump_profile.clone(),
        transport_mode: parsed.transport_mode.clone(),
        dump_completion: parsed.dump_completion.clone(),
        target_pid: parsed.target_pid,
        target_arch: parsed.target_arch.clone(),
        agent_flavor: parsed.agent_flavor.clone(),
        classes_enumerated: parsed.classes_enumerated.or(parsed.class_count),
        classes_dumped: parsed.classes_dumped.unwrap_or(classes.len()),
        classes_skipped: parsed.classes_skipped.or_else(|| {
            parsed
                .classes_enumerated
                .or(parsed.class_count)
                .map(|value| value.saturating_sub(parsed.classes_dumped.unwrap_or(classes.len())))
        }),
        total_classes: classes.len(),
        suspect_count: classes
            .iter()
            .filter(|class| class.category == ClassCategory::Suspect.as_str())
            .count(),
        lambda_count: classes
            .iter()
            .filter(|class| class.category == ClassCategory::Lambda.as_str())
            .count(),
        unknown_count: classes
            .iter()
            .filter(|class| class.category == ClassCategory::Unknown.as_str())
            .count(),
        normal_count: classes
            .iter()
            .filter(|class| class.category == ClassCategory::Normal.as_str())
            .count(),
        classes,
    };

    let json = safe_json_for_html(serde_json::to_string(&payload)?);

    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Class Viewer</title>
  <style>
    :root {{
      --bg: #08111c; --panel: rgba(12,19,31,.94); --panel-2: rgba(15,24,38,.98); --line: rgba(133,152,181,.16);
      --text: #e8eefc; --muted: #8d9cb5; --accent: #63b3ff; --accent-2: #8c7dff; --suspect: #ff8178; --lambda: #f6c768; --unknown: #9cc0ff; --normal: #59d3a6;
      --mono: "Cascadia Code", Consolas, monospace; --sans: "Segoe UI Variable Text", "Trebuchet MS", sans-serif;
      --shadow: 0 26px 64px rgba(0,0,0,.38); --radius: 18px;
    }}
    * {{ box-sizing: border-box; scrollbar-width: thin; scrollbar-color: rgba(113,135,166,.72) rgba(8,12,18,.65); }}
    *::-webkit-scrollbar {{ width: 12px; height: 12px; }}
    *::-webkit-scrollbar-track {{ background: rgba(8,12,18,.65); border-radius: 999px; }}
    *::-webkit-scrollbar-thumb {{ background: linear-gradient(180deg, rgba(86,112,151,.95), rgba(59,78,108,.95)); border-radius: 999px; border: 2px solid rgba(8,12,18,.65); }}
    *::-webkit-scrollbar-thumb:hover {{ background: linear-gradient(180deg, rgba(110,143,191,.98), rgba(74,97,135,.98)); }}
    html, body {{ margin: 0; min-height: 100%; color-scheme: dark; }}
    body {{
      font-family: var(--sans); color: var(--text); padding: 18px;
      background:
        radial-gradient(circle at top left, rgba(99,179,255,.12), transparent 20%),
        radial-gradient(circle at 85% 12%, rgba(140,125,255,.10), transparent 18%),
        radial-gradient(circle at bottom right, rgba(255,129,120,.10), transparent 16%),
        linear-gradient(180deg, #0c1624, #09111c 58%, #07101a);
    }}
    .app {{ max-width: 1540px; margin: 0 auto; display: grid; gap: 16px; }}
    .controls, .list, .detail {{ background: linear-gradient(180deg, rgba(16,24,39,.94), rgba(10,17,28,.94)); border: 1px solid var(--line); border-radius: 24px; box-shadow: var(--shadow); backdrop-filter: blur(16px); }}
    .controls {{ padding: 14px; display: grid; gap: 10px; grid-template-columns: 1.8fr repeat(4, minmax(140px, 1fr)); position: sticky; top: 12px; z-index: 5; }}
    .field {{ display: grid; gap: 6px; }} .field label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    .field input, .field select {{
      width: 100%; padding: 12px 13px; font: inherit; color: var(--text); border-radius: 14px; border: 1px solid rgba(133,152,181,.16);
      background: linear-gradient(180deg, rgba(8,13,22,.98), rgba(7,12,20,.98)); outline: none;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }}
    .field select {{ color-scheme: dark; }}
    .field select option, .field select optgroup {{ background: #0d1522; color: #e8eefc; }}
    .field input:focus, .field select:focus {{ border-color: rgba(99,179,255,.44); box-shadow: 0 0 0 3px rgba(99,179,255,.12); }}
    .field input::placeholder {{ color: #77849a; }}
    .layout {{ display: grid; gap: 16px; grid-template-columns: minmax(360px, 520px) minmax(0, 1fr); min-height: 76vh; }}
    .head {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 18px 18px 12px; border-bottom: 1px solid var(--line); }}
    .head h2 {{ margin: 0; font-size: 18px; }} .subtle {{ color: var(--muted); font-size: 13px; }}
    .list-body {{ padding: 10px; display: grid; gap: 10px; max-height: calc(76vh - 118px); overflow: auto; }}
    .row {{
      width: 100%; color: var(--text); text-align: left; appearance: none; -webkit-appearance: none;
      border: 1px solid rgba(133,152,181,.10); background: linear-gradient(180deg, rgba(11,18,30,.94), rgba(9,15,25,.94));
      border-radius: 18px; padding: 14px; cursor: pointer; transition: border-color .12s ease, transform .12s ease, background .12s ease, box-shadow .12s ease;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }}
    .row:hover {{ transform: translateY(-1px); border-color: rgba(99,179,255,.28); background: linear-gradient(180deg, rgba(16,25,40,.98), rgba(11,19,32,.98)); box-shadow: 0 10px 22px rgba(0,0,0,.18); }}
    .row.active {{ border-color: rgba(99,179,255,.58); background: linear-gradient(180deg, rgba(25,42,65,.96), rgba(17,29,46,.96)); }}
    .row-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }}
    .row-name {{ font-weight: 700; line-height: 1.35; word-break: break-word; font-size: 14px; }}
    .row-origin {{
      margin-top: 8px; color: var(--muted); font-size: 12px; font-family: var(--mono); overflow-wrap: anywhere;
      display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
    }}
    .row-meta, .detail-meta, .reasons {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
    .badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; border: 1px solid transparent; }}
    .suspect {{ color: var(--suspect); background: rgba(255,123,114,.12); border-color: rgba(255,123,114,.22); }}
    .lambda {{ color: var(--lambda); background: rgba(246,199,104,.10); border-color: rgba(246,199,104,.20); }}
    .unknown {{ color: var(--unknown); background: rgba(147,183,255,.10); border-color: rgba(147,183,255,.20); }}
    .normal {{ color: var(--normal); background: rgba(89,211,166,.10); border-color: rgba(89,211,166,.20); }}
    .score {{ color: var(--accent); background: rgba(99,179,255,.10); border-color: rgba(99,179,255,.20); }}
    .pager {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 12px 18px 18px; border-top: 1px solid var(--line); }}
    .pager button {{
      border: 1px solid var(--line); background: linear-gradient(180deg, rgba(11,18,29,.98), rgba(9,15,24,.98));
      color: var(--text); border-radius: 12px; padding: 10px 14px; font: inherit; cursor: pointer;
    }}
    .pager button:disabled {{ opacity: .45; cursor: default; }}
    .detail-body {{ padding: 18px; display: grid; gap: 14px; max-height: calc(76vh - 88px); overflow: auto; }}
    .empty {{ min-height: 420px; display: grid; place-items: center; text-align: center; color: var(--muted); border: 1px dashed rgba(154,170,196,.18); border-radius: 18px; background: rgba(9,14,22,.68); }}
    .title {{ margin: 0; font-size: clamp(24px, 4vw, 40px); line-height: 1.02; letter-spacing: -.05em; word-break: break-word; }}
    .panel {{ background: var(--panel-2); border: 1px solid var(--line); border-radius: 18px; padding: 15px; }}
    .panel h3 {{ margin: 0 0 10px; font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }}
    .reason {{ border: 1px solid var(--line); border-radius: 999px; background: rgba(16,23,35,.98); padding: 7px 11px; font-size: 12px; }}
    .kv {{ display: grid; grid-template-columns: minmax(110px, 170px) minmax(0, 1fr); gap: 10px 16px; }} .kv .k {{ color: var(--muted); font-size: 13px; }} .kv .v {{ overflow-wrap: anywhere; }}
    .mono {{ font-family: var(--mono); font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
    .members {{ display: grid; gap: 10px; }}
    .member {{ border: 1px solid rgba(133,152,181,.10); border-radius: 14px; padding: 12px; background: linear-gradient(180deg, rgba(10,15,23,.94), rgba(8,13,20,.94)); }}
    .member-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }}
    .member-name {{ font-weight: 700; word-break: break-word; font-size: 14px; }}
    .member-meta {{ color: var(--muted); font-size: 12px; }}
    .member-code {{
      margin-top: 8px; padding: 9px 10px; border-radius: 12px; background: rgba(7,11,17,.92);
      border: 1px solid rgba(133,152,181,.08); font-family: var(--mono); font-size: 12px; color: #d3def4; white-space: pre-wrap; overflow-wrap: anywhere;
    }}
    .member-label {{ color: var(--muted); margin-right: 6px; }}
    @media (max-width: 1180px) {{ .controls, .layout {{ grid-template-columns: 1fr; }} .list-body, .detail-body {{ max-height: none; }} }}
    @media (max-width: 700px) {{ body {{ padding: 12px; }} .controls, .head, .detail-body {{ padding-left: 14px; padding-right: 14px; }} .kv {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="app">
    <section class="controls">
      <div class="field"><label for="search">Search</label><input id="search" type="text" placeholder="Class, origin path, loader, reason..." /></div>
      <div class="field"><label for="category">Category</label><select id="category"><option value="all">All</option><option value="suspect">Suspect</option><option value="lambda">Lambda</option><option value="unknown">Unknown</option><option value="normal">Normal</option></select></div>
      <div class="field"><label for="origin">Origin</label><select id="origin"><option value="all">All</option><option value="known">Known path</option><option value="unknown">Unknown path</option><option value="jar">Jar only</option></select></div>
      <div class="field"><label for="sort">Sort</label><select id="sort"><option value="risk">Risk first</option><option value="name">Name</option><option value="methods">Method count</option><option value="fields">Field count</option><option value="origin">Origin path</option></select></div>
      <div class="field"><label for="pageSize">Rows</label><select id="pageSize"><option value="75">75</option><option value="150" selected>150</option><option value="300">300</option></select></div>
    </section>

    <section class="layout">
      <div class="list">
        <div class="head"><h2>Classes</h2><div class="subtle" id="resultsLabel">0 results</div></div>
        <div class="list-body" id="results"></div>
        <div class="pager"><button id="prevPage" type="button">Previous</button><div class="subtle" id="pageLabel">Page 1 / 1</div><button id="nextPage" type="button">Next</button></div>
      </div>
      <div class="detail">
        <div class="head"><h2>Details</h2><div class="subtle" id="detailCounter">Select a class</div></div>
        <div class="detail-body" id="detail"><div class="empty">Select a class on the left to inspect jar/path provenance, URLs, methods and fields.</div></div>
      </div>
    </section>
  </div>
  <script id="dump-data" type="application/json">{json}</script>
  <script>
    const payload = JSON.parse(document.getElementById('dump-data').textContent);
    const state = {{ query: '', category: 'all', origin: 'all', sort: 'risk', pageSize: 150, page: 1, active: null }};
    const list = payload.classes.map((item, index) => ({{
      ...item,
      _i: index,
      _search: [item.name, item.package_name, item.source_reference, item.origin_path, item.origin_source, item.code_source_url, item.resource_url, item.loader, item.loader_class, item.module_name, item.reasons.join(' '), item.flags.join(' ')].join(' ').toLowerCase()
    }}));
    const $ = id => document.getElementById(id);
    const badge = category => category === 'suspect' ? 'suspect' : category === 'lambda' ? 'lambda' : category === 'unknown' ? 'unknown' : 'normal';
    const esc = value => String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
    const categoryWeight = value => value === 'suspect' ? 0 : value === 'lambda' ? 1 : value === 'unknown' ? 2 : 3;
    function filtered() {{
      const q = state.query.trim().toLowerCase();
      const items = list.filter(item => {{
        if (state.category !== 'all' && item.category !== state.category) return false;
        if (state.origin === 'known' && !item.origin_path) return false;
        if (state.origin === 'unknown' && item.origin_path) return false;
        if (state.origin === 'jar' && item.origin_kind !== 'jar') return false;
        if (q && !item._search.includes(q)) return false;
        return true;
      }});
      items.sort((a, b) => {{
        if (state.sort === 'name') return a.name.localeCompare(b.name);
        if (state.sort === 'methods') return (b.method_count - a.method_count) || a.name.localeCompare(b.name);
        if (state.sort === 'fields') return (b.field_count - a.field_count) || a.name.localeCompare(b.name);
        if (state.sort === 'origin') return (a.origin_path || '~').localeCompare(b.origin_path || '~');
        return (categoryWeight(a.category) - categoryWeight(b.category)) || (b.score - a.score) || a.name.localeCompare(b.name);
      }});
      return items;
    }}
    function renderMembers(items) {{
      if (!items.length) return '<div class="member"><div class="member-name">none</div></div>';
      return items.map(item => `
        <div class="member">
          <div class="member-top">
            <div class="member-name">${{esc(item.name || 'Unknown')}}</div>
            <div class="member-meta">${{esc(item.modifiers || 'Unknown modifiers')}}</div>
          </div>
          <div class="member-code"><span class="member-label">Signature:</span>${{esc(item.signature || '-')}}</div>
          ${{item.generic_signature ? `<div class="member-code"><span class="member-label">Generic:</span>${{esc(item.generic_signature)}}</div>` : ''}}
        </div>
      `).join('');
    }}
    function renderDetail(item) {{
      if (!item) {{ $('detailCounter').textContent = 'No class selected'; $('detail').innerHTML = '<div class="empty">No classes match the current filter.</div>'; return; }}
      $('detailCounter').textContent = item.category_title;
      $('detail').innerHTML = `
        <div><h1 class="title">${{esc(item.name)}}</h1><div class="detail-meta"><span class="badge ${{badge(item.category)}}">${{esc(item.category_title)}}</span><span class="badge score">score ${{item.score}}</span><span class="badge">${{item.method_count}} methods</span><span class="badge">${{item.field_count}} fields</span><span class="badge">${{esc(item.origin_kind || 'unknown')}}</span></div></div>
        <div class="panel"><h3>Risk markers</h3><div class="reasons">${{item.reasons.length ? item.reasons.map(reason => `<span class="reason">${{esc(reason)}}</span>`).join('') : '<span class="reason">no extra markers</span>'}}</div></div>
        <div class="panel"><h3>Metadata</h3><div class="kv">
          <div class="k">Package</div><div class="v">${{esc(item.package_name || 'Unknown')}}</div>
          <div class="k">Origin path</div><div class="v mono">${{esc(item.origin_path || 'Unknown')}}</div>
          <div class="k">Origin source</div><div class="v">${{esc(item.origin_source || 'Unknown')}}</div>
          <div class="k">CodeSource URL</div><div class="v mono">${{esc(item.code_source_url || 'Unknown')}}</div>
          <div class="k">Resource URL</div><div class="v mono">${{esc(item.resource_url || 'Unknown')}}</div>
          <div class="k">Loader</div><div class="v">${{esc(item.loader || 'Unknown')}}</div>
          <div class="k">Loader class</div><div class="v">${{esc(item.loader_class || 'Unknown')}}</div>
          <div class="k">Module</div><div class="v">${{esc(item.module_name || 'Unknown')}}</div>
          <div class="k">Source / entry</div><div class="v mono">${{esc(item.source_reference || 'Unknown')}}</div>
          <div class="k">Class modifiers</div><div class="v">${{esc(item.class_modifiers || 'Unknown')}}</div>
          <div class="k">Flags</div><div class="v">${{item.flags.length ? esc(item.flags.join(', ')) : 'Unknown'}}</div>
          <div class="k">Signature</div><div class="v mono">${{esc(item.signature || 'Unknown')}}</div>
          <div class="k">Generic signature</div><div class="v mono">${{esc(item.generic_signature || 'Unknown')}}</div>
        </div></div>
        <div class="panel"><h3>Methods</h3><div class="members">${{renderMembers(item.methods)}}</div></div>
        <div class="panel"><h3>Fields</h3><div class="members">${{renderMembers(item.fields)}}</div></div>
      `;
    }}
    function render() {{
      const items = filtered();
      const pages = Math.max(1, Math.ceil(items.length / state.pageSize));
      if (state.page > pages) state.page = pages;
      const slice = items.slice((state.page - 1) * state.pageSize, state.page * state.pageSize);
      $('resultsLabel').textContent = `${{items.length}} results`;
      $('pageLabel').textContent = `Page ${{state.page}} / ${{pages}}`;
      $('prevPage').disabled = state.page <= 1;
      $('nextPage').disabled = state.page >= pages;
      const fragment = document.createDocumentFragment();
      for (const item of slice) {{
        const node = document.createElement('button');
        node.type = 'button';
        node.className = 'row' + (item._i === state.active ? ' active' : '');
        node.innerHTML = `<div class="row-top"><div class="row-name">${{esc(item.name)}}</div><span class="badge ${{badge(item.category)}}">${{esc(item.category_title)}}</span></div><div class="row-origin">${{esc(item.origin_path || 'Unknown origin path')}}</div><div class="row-meta"><span class="badge score">score ${{item.score}}</span><span class="badge">${{item.method_count}} methods</span><span class="badge">${{item.field_count}} fields</span></div>`;
        node.addEventListener('click', () => {{ state.active = item._i; render(); }});
        fragment.appendChild(node);
      }}
      $('results').replaceChildren(fragment);
      const active = list.find(item => item._i === state.active) || slice[0] || null;
      if (active && state.active === null) state.active = active._i;
      renderDetail(active);
    }}
    $('search').addEventListener('input', e => {{ state.query = e.target.value; state.page = 1; state.active = null; render(); }});
    $('category').addEventListener('change', e => {{ state.category = e.target.value; state.page = 1; state.active = null; render(); }});
    $('origin').addEventListener('change', e => {{ state.origin = e.target.value; state.page = 1; state.active = null; render(); }});
    $('sort').addEventListener('change', e => {{ state.sort = e.target.value; state.page = 1; state.active = null; render(); }});
    $('pageSize').addEventListener('change', e => {{ state.pageSize = Number(e.target.value) || 150; state.page = 1; state.active = null; render(); }});
    $('prevPage').addEventListener('click', () => {{ if (state.page > 1) {{ state.page -= 1; state.active = null; render(); }} }});
    $('nextPage').addEventListener('click', () => {{ const pages = Math.max(1, Math.ceil(filtered().length / state.pageSize)); if (state.page < pages) {{ state.page += 1; state.active = null; render(); }} }});
    render();
  </script>
</body>
</html>"#
    ))
}

fn safe_json_for_html(mut json: String) -> String {
    json = json.replace("</script", "<\\/script");
    json = json.replace('<', "\\u003c");
    json = json.replace('>', "\\u003e");
    json.replace('&', "\\u0026")
}

fn create_report_dir(base_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(base_dir).with_context(|| format!("creating {}", base_dir.display()))?;

    let mut rng = rand::thread_rng();
    for _ in 0..64 {
        let suffix: u32 = rng.gen_range(100_000..=999_999);
        let candidate = base_dir.join(format!("logs-{suffix}"));
        match fs::create_dir(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("creating {}", candidate.display()));
            }
        }
    }

    Err(anyhow!(
        "failed to allocate unique report directory in {}",
        base_dir.display()
    ))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("file");
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("tmp");
    let temp = parent.join(format!("{stem}.{ext}.tmp"));
    fs::write(&temp, bytes).with_context(|| format!("writing {}", temp.display()))?;
    if path.exists() {
        let backup = parent.join(format!("{stem}.{ext}.old"));
        let _ = fs::remove_file(&backup);
        fs::rename(path, &backup).with_context(|| format!("replacing {}", path.display()))?;
        if let Err(err) = fs::rename(&temp, path) {
            let _ = fs::rename(&backup, path);
            return Err(err).with_context(|| format!("replacing {}", path.display()));
        }
        let _ = fs::remove_file(&backup);
        return Ok(());
    }
    fs::rename(&temp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, signature: &str) -> MemberRecord {
        MemberRecord {
            modifiers: "public".to_string(),
            name: name.to_string(),
            signature: signature.to_string(),
            generic_signature: String::new(),
        }
    }

    #[test]
    fn lwjgl_callback_interface_is_not_suspect() {
        let raw = RawClass {
            name: "org.lwjgl.glfw.GLFWCharModsCallbackI".to_string(),
            package_name: "org.lwjgl.glfw".to_string(),
            code_source_url: "file:/C:/libs/lwjgl-glfw-3.3.1.jar".to_string(),
            resource_url:
                "jar:file:/C:/libs/lwjgl-glfw-3.3.1.jar!/org/lwjgl/glfw/GLFWCharModsCallbackI.class"
                    .to_string(),
            loader: "net.fabricmc.loader.impl.launch.knot.KnotClassLoader@157632c9".to_string(),
            loader_class: "net.fabricmc.loader.impl.launch.knot.KnotClassLoader".to_string(),
            module_name: "unnamed module @660acfb".to_string(),
            flags: "interface".to_string(),
            class_modifiers: "public,abstract,interface".to_string(),
            signature: "Lorg/lwjgl/glfw/GLFWCharModsCallbackI;".to_string(),
            method_count: 4,
            field_count: 1,
            methods: vec![
                member("callback", "(JJ)V"),
                member("getCallInterface", "()Lorg/lwjgl/system/libffi/FFICIF;"),
                member("invoke", "(JII)V"),
                member("<clinit>", "()V"),
            ],
            fields: vec![member("CIF", "Lorg/lwjgl/system/libffi/FFICIF;")],
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert_ne!(class.category, ClassCategory::Suspect.as_str());
    }

    #[test]
    fn products_tuple_member_class_is_not_flagged_as_missing_source() {
        let raw = RawClass {
            name: "com.mojang.datafixers.Products$P8".to_string(),
            package_name: "com.mojang.datafixers".to_string(),
            code_source_url: "file:/C:/libs/datafixerupper-6.0.8.jar".to_string(),
            resource_url: "jar:file:/C:/libs/datafixerupper-6.0.8.jar!/com/mojang/datafixers/Products$P8.class".to_string(),
            loader: "net.fabricmc.loader.impl.launch.knot.KnotClassLoader@157632c9".to_string(),
            loader_class: "net.fabricmc.loader.impl.launch.knot.KnotClassLoader".to_string(),
            module_name: "unnamed module @660acfb".to_string(),
            flags: "member".to_string(),
            class_modifiers: "public,static,final".to_string(),
            signature: "Lcom/mojang/datafixers/Products$P8;".to_string(),
            generic_signature: "<F::Lcom/mojang/datafixers/kinds/K1;T1:Ljava/lang/Object;T2:Ljava/lang/Object;T3:Ljava/lang/Object;T4:Ljava/lang/Object;T5:Ljava/lang/Object;T6:Ljava/lang/Object;T7:Ljava/lang/Object;T8:Ljava/lang/Object;>Ljava/lang/Object;".to_string(),
            method_count: 11,
            field_count: 8,
            methods: vec![
                member("<init>", "(Lcom/mojang/datafixers/kinds/App;)V"),
                member("apply", "(Lcom/mojang/datafixers/kinds/Applicative;)Lcom/mojang/datafixers/kinds/App;"),
                member("t1", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t2", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t3", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t4", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t5", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t6", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t7", "()Lcom/mojang/datafixers/kinds/App;"),
                member("t8", "()Lcom/mojang/datafixers/kinds/App;"),
            ],
            fields: vec![
                member("t1", "Lcom/mojang/datafixers/kinds/App;"),
                member("t2", "Lcom/mojang/datafixers/kinds/App;"),
                member("t3", "Lcom/mojang/datafixers/kinds/App;"),
                member("t4", "Lcom/mojang/datafixers/kinds/App;"),
                member("t5", "Lcom/mojang/datafixers/kinds/App;"),
                member("t6", "Lcom/mojang/datafixers/kinds/App;"),
                member("t7", "Lcom/mojang/datafixers/kinds/App;"),
                member("t8", "Lcom/mojang/datafixers/kinds/App;"),
            ],
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert!(
            !class
                .reasons
                .iter()
                .any(|reason| reason.contains("source file"))
        );
        assert_ne!(class.category, ClassCategory::Suspect.as_str());
        assert!(!class.source_reference.is_empty());
    }

    #[test]
    fn anonymous_inner_library_class_is_not_suspect_from_compiler_names() {
        let raw = RawClass {
            name: "com.google.gson.internal.bind.ReflectiveTypeAdapterFactory$1".to_string(),
            package_name: "com.google.gson.internal.bind".to_string(),
            code_source_url: "file:/C:/libs/gson-2.10.jar".to_string(),
            resource_url: "jar:file:/C:/libs/gson-2.10.jar!/com/google/gson/internal/bind/ReflectiveTypeAdapterFactory$1.class".to_string(),
            flags: "anonymous".to_string(),
            methods: vec![
                member("<init>", "(Ljava/lang/Object;)V"),
                member("write", "(Lcom/google/gson/stream/JsonWriter;Ljava/lang/Object;)V"),
                member("readIntoArray", "(Lcom/google/gson/stream/JsonReader;I[Ljava/lang/Object;)V"),
                member("readIntoField", "(Lcom/google/gson/stream/JsonReader;Ljava/lang/Object;)V"),
            ],
            fields: vec![
                member("val$blockInaccessible", "Z"),
                member("val$accessor", "Ljava/lang/reflect/Method;"),
                member("val$field", "Ljava/lang/reflect/Field;"),
                member("this$0", "Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;"),
            ],
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert!(class.score < 95);
        assert_ne!(class.category, ClassCategory::Suspect.as_str());
    }

    #[test]
    fn trusted_jrt_class_is_not_suspect_from_short_tokens() {
        let raw = RawClass {
            name: "jdk.internal.util.SystemProps$Raw".to_string(),
            package_name: "jdk.internal.util".to_string(),
            resource_url: "jrt:/java.base/jdk/internal/util/SystemProps$Raw.class".to_string(),
            loader: "bootstrap".to_string(),
            loader_class: "bootstrap".to_string(),
            module_name: "java.base".to_string(),
            flags: "member".to_string(),
            methods: vec![
                member("cmdProperties", "()Ljava/util/HashMap;"),
                member("propDefault", "(I)Ljava/lang/String;"),
            ],
            fields: vec![
                member("_os_arch_NDX", "I"),
                member("_os_name_NDX", "I"),
                member("FIXED_LENGTH", "I"),
            ],
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert_eq!(class.category, ClassCategory::Normal.as_str());
    }

    #[test]
    fn mapped_or_hashed_class_name_remains_suspect() {
        let raw = RawClass {
            name: "net.minecraft.class_7706$1ItemGroupPosition$0ad2899f017540c1b796df33576c0086"
                .to_string(),
            package_name: "net.minecraft".to_string(),
            code_source_url: "file:/C:/libs/client.jar".to_string(),
            resource_url: "jar:file:/C:/libs/client.jar!/net/minecraft/class_7706$1ItemGroupPosition$0ad2899f017540c1b796df33576c0086.class".to_string(),
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert_eq!(class.category, ClassCategory::Suspect.as_str());
    }

    #[test]
    fn missing_provenance_without_strong_signals_is_unknown() {
        let raw = RawClass {
            name: "com.example.FeatureToggle".to_string(),
            package_name: "com.example".to_string(),
            ..RawClass::default()
        };

        let class = build_report_class(raw).expect("report class");
        assert_eq!(class.category, ClassCategory::Unknown.as_str());
    }

    #[test]
    fn core_profile_does_not_flag_missing_provenance_as_unknown() {
        let raw = RawClass {
            name: "com.example.FeatureToggle".to_string(),
            package_name: "com.example".to_string(),
            source_file: "FeatureToggle.java".to_string(),
            ..RawClass::default()
        };

        let class = build_report_class_for_dump(raw, Some("core")).expect("report class");
        assert_ne!(class.category, ClassCategory::Unknown.as_str());
        assert_ne!(class.category, ClassCategory::Suspect.as_str());
    }

    #[test]
    fn inspect_dump_file_supports_extended_headers() {
        let temp_dir = std::env::temp_dir().join("jlivef-dump-inspect-test");
        let _ = fs::create_dir_all(&temp_dir);
        let raw_path = temp_dir.join("extended.rawdump");
        fs::write(
            &raw_path,
            "\
JLIVEF_DUMP_V4
ProtocolVersion: 4
SessionId: abc-123
DumpProfile: extended
TransportMode: runtime_attach
DumpCompletion: partial_success
TargetPid: 4242
DetectedJavaMajor: 21
TargetArch: x64
AgentFlavor: modern_jvmti
ClassesEnumerated: 5
ClassesDumped: 1
ClassesSkipped: 4
@@CLASS
Name: com.example.Test
Package: com.example
MethodCount: 0
FieldCount: 0
@@END
",
        )
        .expect("write raw dump");

        let inspection = inspect_dump_file(&raw_path).expect("inspect dump");
        assert_eq!(inspection.protocol_version.as_deref(), Some("4"));
        assert_eq!(inspection.session_id.as_deref(), Some("abc-123"));
        assert_eq!(inspection.dump_profile.as_deref(), Some("extended"));
        assert_eq!(inspection.transport_mode.as_deref(), Some("runtime_attach"));
        assert_eq!(
            inspection.dump_completion.as_deref(),
            Some("partial_success")
        );
        assert_eq!(inspection.target_pid, Some(4242));
        assert_eq!(inspection.target_java.as_deref(), Some("21"));
        assert_eq!(inspection.target_arch.as_deref(), Some("x64"));
        assert_eq!(inspection.agent_flavor.as_deref(), Some("modern_jvmti"));
        assert_eq!(inspection.classes_enumerated, Some(5));
        assert_eq!(inspection.classes_dumped, 1);
        assert_eq!(inspection.classes_skipped, Some(4));
    }

    #[test]
    fn parse_method_record_supports_simple_format() {
        let method = parse_method_record("setProfile(Ljava/lang/String;)V");
        assert_eq!(method.modifiers, "");
        assert_eq!(method.name, "setProfile");
        assert_eq!(method.signature, "(Ljava/lang/String;)V");
        assert_eq!(method.generic_signature, "");
    }

    #[test]
    fn parse_field_record_supports_simple_format() {
        let field = parse_field_record("profileName : Ljava/lang/String;");
        assert_eq!(field.modifiers, "");
        assert_eq!(field.name, "profileName");
        assert_eq!(field.signature, "Ljava/lang/String;");
        assert_eq!(field.generic_signature, "");
    }

    #[test]
    fn process_dump_file_creates_logs_outputs() {
        let temp_dir = std::env::temp_dir().join("jlivef-dump-report-test");
        let _ = fs::create_dir_all(&temp_dir);
        let raw_path = temp_dir.join("sample.rawdump");
        fs::write(
            &raw_path,
            "\
JLIVEF_DUMP_V2
TargetJava: 17
ClassCount: 1
@@CLASS
Name: com.example.Test
Package: com.example
CodeSourceUrl: file:/C:/libs/test.jar
ResourceUrl: jar:file:/C:/libs/test.jar!/com/example/Test.class
MethodCount: 1
Method: public | test()V | Generic=-
FieldCount: 0
@@END
",
        )
        .expect("write raw dump");

        let processed = process_dump_file(&raw_path).expect("process dump");
        assert!(processed.report_path.exists());
        assert!(processed.html_path.exists());
        assert!(processed.index_path.exists());
        let report_dir_name = processed
            .report_path
            .parent()
            .and_then(|path| path.file_name())
            .and_then(|value| value.to_str())
            .unwrap_or("");
        assert!(report_dir_name.starts_with("logs-"));
        assert!(raw_path.exists());
    }
}
