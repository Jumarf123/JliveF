# JliveF Source Export

Clean source export for building `JliveF` from source.

## Build

```powershell
cargo build --profile product --locked
```

Binary output:

```text
target\product\JliveF.exe
```

## Included

- Rust sources for the main application
- Embedded `external_dumper` helper source
- `agents` source files (`src`, `include`, `CMakeLists.txt`)
- project resources needed for the repository build

## Not Included

- `.git`
- `target/` and other build artifacts
- `product/`
- generated `results/`
- real YARA rules from `screenshare_toolkit/rust_project/yara`

## YARA Note

This export intentionally ships without `.yar` / `.yara` rules.
The directory `screenshare_toolkit/rust_project/yara` contains only a stub note, and the project is expected to build without public YARA signatures.
