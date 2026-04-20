# JVMTI Agent build notes

Requirements:
- CMake 3.20+
- MSVC/Build Tools (x64)
- JDK headers are already vendored in `include/`

Build steps (from `agents/`):
```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Outputs:
- `agents/java8/JVMTI_Agent.dll`
- `agents/java17/JVMTI_Agent.dll`
- `agents/java21/JVMTI_Agent.dll`

All three DLLs share the same source but use a compile-time `TARGET_JAVA_VERSION` define to select the JVMTI version constant.
