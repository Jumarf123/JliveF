# Анализ оригинального проекта

## Что это за проект

Исходный `Screenshare Tool` — Windows-only C/C++ утилита для ручного screenshare-аудита игрока. Проект не выглядит как обычный игровой античит в фоне; это набор точечных проверок, которые оператор запускает вручную и интерпретирует сам.

## Точка входа

- `Screenshare Tool/main.cpp`
  - Проверяет запуск от администратора.
  - Проверяет наличие внешнего `memory.exe`.
  - Последовательно прогоняет все checks.
  - В конце вешает low-level hooks мыши/клавиатуры и держит их до нажатия `Delete`.

## Архитектура по папкам

### `checks/`

- `bam`
  - Читает `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`.
  - Ищет бинарные значения `\Device\...`.
  - Конвертирует FILETIME и пытается отсеивать подписанные файлы.

- `devices`
  - Получает мыши через WMI и парсит VID/PID.
  - Проверяет `MouseKeys` по реестру.
  - Смотрит USB-ветку и пытается выводить unplugged devices по метаданным веток.

- `disk`
  - Эвристика на замену/подключение дисков через `System Volume Information`.

- `eventlog`
  - Проверяет путь eventlog в реестре.
  - Через Event Log API ищет Kernel-General EventID 22 как след смены времени.

- `import code`
  - Ищет строки вроде `Invoke-RestMethod`/`Invoke-Expression` в памяти сервисов.
  - Для этого запускает внешний memory scanner.

- `macros`
  - Сканирует известные macro-файлы и директории многих брендов.
  - Ищет read-only bypass, строки логов и свежие модификации.

- `memory`
  - `userproc.cpp`: explorer/PcaSvc/PlugPlay через внешний `memory.exe`.
  - `kernelproc.cpp`: полу-ручная процедура с дампами `csrss` плюс `fsutil usn`.
  - `javaw.c`: прямое чтение памяти `javaw.exe` / `Minecraft.Windows.exe`.

- `mods`
  - Ищет jar-моды, изменённые уже после запуска Minecraft.

- `onboard memory macros`
  - Низкоуровневые хуки клавиатуры/мыши и простая эвристика на 0ms/repeated intervals.

- `system`
  - Проверки сетевых шар, Prefetch, времени старта сервисов, EventLog path.

- `task scheduler`
  - Сканы памяти процесса `Schedule` через внешний memory scanner.

- `usn journal`
  - Читает `fsutil usn readjournal`.
  - Экспортирует txt-файлы для ручной проверки rename/special-char/macro traces.

- `virtual machines`
  - Подключён большой header-only `VMAware`.

### `miscellaneous/`

- `digital signature`
  - Проверка цифровой подписи через `WinVerifyTrust`.

- `gui`
  - Только цвет текста консоли.

- `wmi`
  - Обёртка над COM/WMI.

## Слабые места оригинала

### 1. Несовпадение имени memory scanner

- `main.hpp` ожидает `memory.exe`.
- `checks/import code/importcode.cpp` и `checks/macros/macroscanner.cpp` вызывают `memory scanner.exe`.
- Это прямой функциональный баг: часть сканов ломается, если рядом лежит только один ожидаемый бинарник.

### 2. Сильная зависимость от shell-команд

- `system()`, `_wsystem()` и пайпы под `fsutil/findstr`.
- Проверки сложнее тестировать, а error-handling фрагментирован.

### 3. Ручное управление памятью и COM

- Много `malloc/free`, `new/delete`, сырых HANDLE/COM указателей и повторяющегося шаблонного кода.
- Для Rust-порта это естественная зона улучшения.

### 4. Непоследовательность уровней проверок

- Часть checks — чисто автоматические.
- Часть зависит от внешнего memory scanner.
- Часть требует ручного дампа `csrss`.
- Часть выводит просто “посмотри руками”.

## Что сохранено в Rust-порте

- Разделение на доменные блоки.
- Ориентация на Windows.
- Проверки на memory-based traces, BAM, USN, моды, macro files, services, VM и hooks.

## Что улучшено в Rust-порте

- Единый интерактивный запуск без аргументов CLI.
- Чёткое меню `1..4`.
- Единый формат отчётов и заметок.
- Поддержка и `memory.exe`, и `memory scanner.exe`.
- Централизованные PowerShell/native helper-слои.
- Артефакты USN экспортируются в `scan_exports`.
- Добавлены unit tests на чистые парсеры.
