# Jlivef — Release Notes / Update 23.04.2026

*add hameleon + faker detect /23.04*
<p align="center">
  <a href="#ru"><img alt="Русский" src="https://img.shields.io/badge/Русский-Read-1f6feb?style=for-the-badge" /></a>
  <a href="#en"><img alt="English" src="https://img.shields.io/badge/English-Read-1f6feb?style=for-the-badge" /></a>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/Version-23.04.2026-2ea043?style=flat-square" />
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows-2ea043?style=flat-square" />
  <img alt="Type" src="https://img.shields.io/badge/Type-Screenshare%20Toolkit-b7410e?style=flat-square" />
</p>

---

## Navigation

- [Русский](#ru)
- [English](#en)

---

<a name="ru"></a>
## Русский

### О релизе

**Jlivef** — это Windows toolkit для screenshare-проверок, который объединяет несколько утилит в одном интерфейсе для удобного анализа системы, сетевых параметров и возможных инжектов.

### Как использовать

1. Скачайте и распакуйте архив.
2. Запустите программу.
3. Выберите нужный модуль.
4. Дождитесь завершения проверки и изучите результат.

### Описание модулей

#### 1. Internal / External Dumper

**Internal dumper**
- **complex** — собирает максимально возможные данные о классах, включая путь к исходному файлу и другую информацию. Не рекомендуется для Lunar и подобных клиентов.
- **simple** — собирает только методы и поля классов.

**External dumper**
- Работает на Java 9+.
- Рекомендуется как наиболее безопасный вариант.

**Как использовать:**
1. Выберите процесс Minecraft.
2. Дождитесь завершения дампа.
3. Перейдите по пути, указанному в программе, и откройте `.txt` файл с результатом.

#### 2. Network Scanner

Проверяет сетевые параметры и ветки реестра на запрещённые или подозрительные значения.

**Результаты:**
- **Нарушений нет** — всё в норме.
- **Найдено нарушение** — возможны махинации с интернетом или изменение сетевых параметров.

#### 3. WinLiveInfo

Графический просмотрщик системной информации со сбором логов через PowerShell.

**Примечание:**
- В основном интерес представляет раздел **Functions**.
- Для просмотра результатов используйте **Actions → открыть в HTML**.

#### 4. JVMTI Detector

Ищет сигнатуры JVMTI/JNI-инжектов в процессах `javaw.exe`.

**Коды результата:**
- `code 10` — инжект не обнаружен.
- `code 50` — возможен инжект.
- `code 80` — подтверждённый инжект.

#### 5. Found Faker

Запускает анализ Wi‑Fi, ARP и hosted network для обнаружения faker.

#### 6. Bypass Finder

Ищет различные bypass-методики и подозрительные обходы на устройстве.

#### 7. Launch Scripts

Ищет факты запуска `.bat`, `.py` и других скриптов.

**Примечание:**
- На текущий момент модуль может работать нестабильно.

#### 8. Screenshare Tools

Дополнительный набор утилит для проверки компьютера:
- анализ `BAM`
- анализ `USN Journal`
- проверка `macros`
- проверка `scheduler`
- анализ сервисов
- и другие вспомогательные инструменты

#### 9. proxy bypass found

- Анализирует практически все сетевые артефакты для поиска `faker / hameleon` и подобных читов

### Автор

**Jumarf**

---

<a name="en"></a>
## English

### About this release

**Jlivef** is a Windows toolkit for screenshare checks that combines multiple utilities in one interface for convenient system analysis, network inspection, and injection detection.

### How to use

1. Download and extract the archive.
2. Launch the program.
3. Select the required module.
4. Wait for the scan to finish and review the result.

### Module overview

#### 1. Internal / External Dumper

**Internal dumper**
- **complex** — collects as much class-related data as possible, including the path to the source file and other details. Not recommended for Lunar and similar clients.
- **simple** — collects only class methods and fields.

**External dumper**
- Works on Java 9+.
- Recommended as the safest available option.

**How to use:**
1. Select the Minecraft process.
2. Wait until the dump is completed.
3. Open the path shown in the program and review the generated `.txt` dump file.

#### 2. Network Scanner

Checks network-related parameters and registry branches for prohibited or suspicious values.

**Results:**
- **No violations found** — everything is normal.
- **Violation found** — possible internet manipulation or modified network parameters.

#### 3. WinLiveInfo

A graphical system information viewer with PowerShell-based log collection.

**Note:**
- The main section of interest is **Functions**.
- To view the results, use **Actions → open in HTML**.

#### 4. JVMTI Detector

Searches for JVMTI/JNI injection signatures in `javaw.exe` processes.

**Result codes:**
- `code 10` — no injection detected.
- `code 50` — possible injection.
- `code 80` — confirmed injection.

#### 5. Found Faker

Runs Wi‑Fi, ARP, and hosted network analysis to detect faker-related activity.

#### 6. Bypass Finder

Searches for various bypass methods and suspicious system workarounds.

#### 7. Launch Scripts

Looks for execution traces of `.bat`, `.py`, and other scripts.

**Note:**
- At the moment, this module may work inconsistently.

#### 8. Screenshare Tools

An additional set of utilities for deeper computer inspection:
- `BAM` analysis
- `USN Journal` analysis
- `macros` inspection
- `scheduler` inspection
- services analysis
- and other supporting tools

#### 9. proxy bypass found
- analysis all internet artifacts for find `faker / hameleon` proxy bypass
### Author

**Jumarf**
