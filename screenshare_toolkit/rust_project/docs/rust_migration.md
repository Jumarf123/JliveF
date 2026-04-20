# Карта переноса в Rust

## Новая структура

```text
rust_project/
  src/
    app/
    core/
    modules/
      environment/
      forensics/
      processes/
      interactive/
    ui/
  docs/
  tests/
```

## Соответствие меню и исходного проекта

### Модуль 1. Среда и устройства

Перенесено из:

- `main.hpp` — admin check
- `checks/virtual machines`
- `checks/devices`
- `checks/system/localhost.c`
- `checks/eventlog`
- `checks/disk`
- `checks/system/prochandler.cpp`

Содержимое Rust:

- права администратора;
- VM heuristics;
- список мышей и VID/PID;
- MouseKeys;
- текущая USB-топология;
- сетевые шары;
- eventlog path и время-смена по Kernel-General;
- дисковая эвристика;
- сервисы и их время старта.

### Модуль 2. Форензика диска и журнала

Перенесено из:

- `checks/bam`
- `checks/usn journal`
- `checks/task scheduler`

Содержимое Rust:

- BAM registry audit;
- USN Journal after-boot heuristic;
- экспорт USN-артефактов в `scan_exports/usn`;
- memory-based traces процесса `Schedule`.

### Модуль 3. Память, макросы и процессы

Перенесено из:

- `checks/import code`
- `checks/macros/macroscanner.cpp`
- `checks/memory/userproc.cpp`
- `checks/memory/javaw.c`
- `checks/macros/macros.c`
- `checks/mods/mods.c`

Содержимое Rust:

- централизованный `memory.exe` launcher;
- explorer/PcaSvc/PlugPlay checks;
- import-code patterns;
- macro strings в памяти;
- java/minecraft memory scan;
- macro files/read-only/content checks;
- suspicious mods after game start.

### Модуль 4. Интерактивные хуки

Перенесено из:

- `checks/onboard memory macros/mousehook.c`
- `checks/onboard memory macros/keyboardhook.c`

Содержимое Rust:

- `WH_MOUSE_LL`;
- `WH_KEYBOARD_LL`;
- детекция 0ms delay;
- repeated-identical-interval эвристика;
- остановка по `Delete`.

## Что изменено концептуально

- Ручной разношёрстный вывод заменён на единый `ModuleReport`.
- Вспомогательные shell/Powershell/native вызовы вынесены в `core`.
- Логика разбита по отдельным папкам и мелким файлам, а не через один giant include graph.
- `memory.exe` больше не привязан к одному жёсткому имени файла.
- VM detection и signature verification теперь берутся из оригинальных нативных компонентов через FFI bridge.
