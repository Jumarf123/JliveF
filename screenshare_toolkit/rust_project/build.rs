use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir missing"));
    let original_root = manifest_dir.join("..").join("Screenshare Tool");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("out dir missing"));
    let yara_dir = manifest_dir.join("yara");
    configure_windows_link_search();

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("native").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        original_root
            .join("checks")
            .join("virtual machines")
            .join("vmaware.hpp")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        original_root
            .join("miscellaneous")
            .join("digital signature")
            .join("trustverify.cpp")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        original_root
            .join("miscellaneous")
            .join("digital signature")
            .join("trustverify.hpp")
            .display()
    );
    println!("cargo:rerun-if-changed={}", yara_dir.display());

    let mut embedded = String::from("pub static EMBEDDED_YARA_RULES: &[(&str, u8, &[u8])] = &[\n");
    let mut files = match fs::read_dir(&yara_dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|value| value.path()))
            .filter(|path| {
                path.extension()
                    .and_then(|value| value.to_str())
                    .map(|value| matches!(value, "yar" | "yara"))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            println!(
                "cargo:warning=YARA directory not found at {}; building without embedded rules",
                yara_dir.display()
            );
            Vec::new()
        }
        Err(error) => panic!(
            "failed to read yara directory {}: {error}",
            yara_dir.display()
        ),
    };
    files.sort();

    for path in files {
        let namespace = path
            .file_stem()
            .and_then(|value| value.to_str())
            .expect("invalid yara file name");
        let key = namespace
            .bytes()
            .fold(0x5Au8, |acc, byte| acc.rotate_left(1) ^ byte);
        let encoded = fs::read(&path)
            .expect("failed to read yara file")
            .into_iter()
            .map(|byte| byte ^ key)
            .collect::<Vec<_>>();

        embedded.push_str(&format!("    ({:?}, {key}, &[\n", namespace));
        for chunk in encoded.chunks(20) {
            embedded.push_str("        ");
            for byte in chunk {
                embedded.push_str(&format!("{byte}, "));
            }
            embedded.push('\n');
        }
        embedded.push_str("    ]),\n");
    }
    embedded.push_str("];\n");
    fs::write(out_dir.join("embedded_yara_rules.rs"), embedded)
        .expect("failed to generate embedded_yara_rules.rs");

    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file(manifest_dir.join("native").join("vm_bridge.cpp"))
        .file(manifest_dir.join("native").join("signature_bridge.cpp"))
        .file(
            original_root
                .join("miscellaneous")
                .join("digital signature")
                .join("trustverify.cpp"),
        )
        .include(original_root.join("checks").join("virtual machines"))
        .include(
            original_root
                .join("miscellaneous")
                .join("digital signature"),
        )
        .compile("ss_native");
}

fn configure_windows_link_search() {
    if env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }

    println!("cargo:rerun-if-env-changed=VCToolsInstallDir");
    println!("cargo:rerun-if-env-changed=WindowsSdkDir");
    println!("cargo:rerun-if-env-changed=WindowsSdkVersion");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        _ => return,
    };

    if let Some(msvc_root) = resolve_msvc_root() {
        for suffix in ["lib", "lib\\onecore"] {
            let candidate = msvc_root.join(suffix).join(arch);
            if candidate.is_dir() {
                println!("cargo:rustc-link-search=native={}", candidate.display());
            }
        }
    }

    if let Some((sdk_root, sdk_version)) = resolve_windows_sdk_root() {
        for suffix in ["ucrt", "um"] {
            let candidate = sdk_root.join(sdk_version.as_str()).join(suffix).join(arch);
            if candidate.is_dir() {
                println!("cargo:rustc-link-search=native={}", candidate.display());
            }
        }
    }
}

fn resolve_msvc_root() -> Option<PathBuf> {
    if let Ok(path) = env::var("VCToolsInstallDir") {
        let candidate = PathBuf::from(path);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    let base =
        Path::new(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC");
    latest_version_dir(base)
}

fn resolve_windows_sdk_root() -> Option<(PathBuf, String)> {
    if let (Ok(dir), Ok(version)) = (env::var("WindowsSdkDir"), env::var("WindowsSdkVersion")) {
        let root = PathBuf::from(dir).join("Lib");
        let version = version.trim_matches(['\\', '/']).to_string();
        if root.join(&version).is_dir() {
            return Some((root, version));
        }
    }

    let root = PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\Lib");
    let version = latest_version_name(&root)?;
    Some((root, version))
}

fn latest_version_dir(base: &Path) -> Option<PathBuf> {
    let name = latest_version_name(base)?;
    Some(base.join(name))
}

fn latest_version_name(base: &Path) -> Option<String> {
    let mut versions = fs::read_dir(base)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| starts_with_digit(name))
        .collect::<Vec<_>>();
    versions.sort();
    versions.pop()
}

fn starts_with_digit(value: &str) -> bool {
    value.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}
