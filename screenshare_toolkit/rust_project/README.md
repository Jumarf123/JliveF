# rust_project

Rust-порт проекта `Screenshare Tool` с новой структурой по модулям и интерактивным меню.

## Запуск

1. Соберите проект:

```powershell
cargo build --release
```

2. Запустите итоговый `rust_project.exe` обычным двойным кликом или из PowerShell.

3. Внутри exe откроется меню:

```text
1. Среда и устройства
2. Форензика диска и журнала
3. Память, макросы и процессы
```

## Структура

- `src/app` — вход в приложение и orchestration меню.
- `src/core` — общие типы отчётов, shell/PowerShell helper-слой, парсеры и пути.
- `src/modules/environment` — права, VM, eventlog, диски, шары, устройства, сервисы.
- `src/modules/forensics` — BAM, USN Journal, экспорт артефактов, scheduler.
- `src/modules/processes` — `memory.exe`, макросы, java scan, mods.
- `src/modules/interactive` — low-level keyboard/mouse hooks.
- `docs` — анализ оригинального проекта, security-review, карта переноса и тестирование.
- `native` + `build.rs` — мосты к оригинальным `VMAware` и `TrustVerify`.

## Важное отличие от оригинала

Оригинальный C/C++ проект частично ожидал `memory.exe`, а частично `memory scanner.exe`. Rust-порт поддерживает оба имени и пытается найти любой совместимый memory scanner рядом с исполняемым файлом.

Проверить покрытие по исходным checks можно в [docs/parity_matrix.md](C:\Users\jumarf\Desktop\addtojlivef\screenshare-tool-main\screenshare-tool-main\rust_project\docs\parity_matrix.md).
