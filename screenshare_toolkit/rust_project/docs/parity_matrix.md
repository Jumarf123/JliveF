# Матрица соответствия original -> Rust

## Основная последовательность `main.cpp`

| Original check | Исходный файл | Статус в Rust |
|---|---|---|
| `IsRunningAsAdmin()` | `main.hpp` | Перенесено в `modules/environment/admin.rs` |
| `checkMemoryExe()` | `main.hpp` | Перенесено и улучшено в `modules/processes/memory_tool.rs` |
| `VirtualMachine()` | `main.hpp` + `vmaware.hpp` | Перенесено через нативный bridge к оригинальному `VMAware` |
| `MacroStrings()` | `checks/macros/macroscanner.cpp` | Перенесено в `modules/processes/macro_strings.rs` |
| `ExecutedFiles()` | `checks/memory/userproc.cpp` | Перенесено в `modules/processes/executed_files.rs` |
| `UnpluggedDevices()` | `checks/devices/devices.cpp` | Перенесено нативной registry-enumeration в `modules/environment/devices.rs` |
| `MouseCheck()` | `checks/devices/mouse.cpp` | Перенесено в `modules/environment/devices.rs` |
| `MouseKeys()` | `checks/devices/keys.c` | Перенесено в `modules/environment/devices.rs` |
| `USNJournalCleared()` | `checks/usn journal/journal.cpp` | Перенесено в `modules/forensics/journal.rs` |
| `SystemInformer()` | `checks/system/prochacker.cpp` | Перенесено в `modules/environment/system_informer.rs` |
| `RestartedProcesses()` | `checks/system/prochandler.cpp` | Перенесено в `modules/environment/services.rs` |
| `EventlogBypass()` | `checks/eventlog/evthandler.cpp` | Перенесено в `modules/environment/eventlog.rs` |
| `SystemTimeChange()` | `checks/eventlog/evtquery.cpp` | Перенесено в `modules/environment/eventlog.rs` |
| `LocalHost()` | `checks/system/localhost.c` | Перенесено в `modules/environment/network.rs` |
| `bam()` | `checks/bam/bam.cpp` | Перенесено в `modules/forensics/bam.rs` |
| `SuspiciousMods()` | `checks/mods/mods.c` | Перенесено в `modules/processes/mods.rs` |
| `ReplacedDisks()` | `checks/disk/disk.cpp` | Перенесено в `modules/environment/disks.rs` |
| `ImportCode()` | `checks/import code/importcode.cpp` | Перенесено в `modules/processes/import_code.rs` |
| `TaskScheduler()` | `checks/task scheduler/scheduler.cpp` | Перенесено в `modules/forensics/scheduler.rs` |
| `Javaw()` | `checks/memory/javaw.c` | Перенесено в `modules/processes/java_scan.rs` |
| `csrss()` | `checks/memory/kernelproc.cpp` | Перенесено как manual workflow в `modules/processes/csrss.rs` |
| `USNJournal()` | `checks/usn journal/fsutil.cpp` | Перенесено в `modules/forensics/journal.rs` |
| `Macros()` | `checks/macros/macros.c` | Перенесено в `modules/processes/macro_files.rs` |
| `InstallMouseHook()/InstallKeyboardHook()` | `checks/onboard memory macros/*` | Перенесено в `modules/interactive/hooks.rs` |

## Нативные bridges

| Original native code | Как используется |
|---|---|
| `checks/virtual machines/vmaware.hpp` | Компилируется через `build.rs` и вызывается из `core/native.rs` |
| `miscellaneous/digital signature/trustverify.cpp` | Компилируется через `build.rs` и вызывается из `core/native.rs` |

## Что всё ещё отличается по форме, но не по цели

- В исходнике всё шло одной длинной последовательностью в `main.cpp`; в Rust это разделено на 4 меню-модуля.
- Часть сообщений переработана в структурированные отчёты вместо сырого `printf`.
- Rust-порт намеренно не удаляет пользовательские dump-файлы после `csrss`-анализа, хотя исходник удалял часть временных файлов.
