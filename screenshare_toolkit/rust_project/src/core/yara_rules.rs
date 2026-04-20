use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, anyhow};

include!(concat!(env!("OUT_DIR"), "/embedded_yara_rules.rs"));

static COMPILED_RULES: OnceLock<Result<yara_x::Rules, String>> = OnceLock::new();
static SCAN_CACHE: OnceLock<Mutex<HashMap<PathBuf, Vec<String>>>> = OnceLock::new();
thread_local! {
    static THREAD_SCANNER: RefCell<Option<yara_x::Scanner<'static>>> = const { RefCell::new(None) };
}

pub fn available() -> bool {
    !EMBEDDED_YARA_RULES.is_empty()
}

pub fn scan_file(path: &Path) -> Result<Vec<String>> {
    if !available() || !path.is_file() {
        return Ok(Vec::new());
    }

    let cache = SCAN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .expect("YARA-X cache poisoned")
        .get(path)
        .cloned()
    {
        return Ok(cached);
    }

    let rules = compiled_rules()?;
    let mut matched = THREAD_SCANNER.with(|slot| -> Result<Vec<String>> {
        let mut slot = slot.borrow_mut();
        let scanner = slot.get_or_insert_with(|| yara_x::Scanner::new(rules));
        let results = scanner
            .scan_file(path)
            .with_context(|| format!("yara-x scan failed for {}", path.display()))?;

        Ok(results
            .matching_rules()
            .map(|rule| {
                let namespace = rule.namespace();
                if namespace.is_empty() || namespace == "default" {
                    rule.identifier().to_string()
                } else {
                    namespace.to_string()
                }
            })
            .collect::<Vec<_>>())
    })?;
    matched.sort();
    matched.dedup();

    cache
        .lock()
        .expect("YARA-X cache poisoned")
        .insert(path.to_path_buf(), matched.clone());

    Ok(matched)
}

fn compiled_rules() -> Result<&'static yara_x::Rules> {
    match COMPILED_RULES.get_or_init(compile_rules) {
        Ok(rules) => Ok(rules),
        Err(error) => Err(anyhow!("failed to compile embedded YARA-X rules: {error}")),
    }
}

fn compile_rules() -> Result<yara_x::Rules, String> {
    let mut compiler = yara_x::Compiler::new();

    for (namespace, key, encoded_source) in EMBEDDED_YARA_RULES {
        let source = encoded_source
            .iter()
            .map(|byte| byte ^ key)
            .collect::<Vec<_>>();
        let source = String::from_utf8(source).map_err(|error| error.to_string())?;
        compiler.new_namespace(namespace);
        compiler
            .add_source(
                yara_x::SourceCode::from(source.as_str()).with_origin(format!("{namespace}.yar")),
            )
            .map_err(|error| error.to_string())?;
    }

    Ok(compiler.build())
}
