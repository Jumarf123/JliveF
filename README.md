# Jlivef — Windows Toolkit / **Update 15.04.2026**

<p align="center">
  <a href="#ru"><img alt="Русский" src="https://img.shields.io/badge/Русский-Read-1f6feb?style=for-the-badge" /></a>
  <a href="#en"><img alt="English" src="https://img.shields.io/badge/English-Read-1f6feb?style=for-the-badge" /></a>
</p>

<p align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Platform-Windows-2ea043?style=flat-square" />
  <img alt="Toolkit" src="https://img.shields.io/badge/Type-Windows%20Toolkit-b7410e?style=flat-square" />
  <img alt="Output" src="https://img.shields.io/badge/Output-TXT-8250df?style=flat-square" />
  <img alt="Use case" src="https://img.shields.io/badge/Use%20Case-System%20Analysis-0969da?style=flat-square" />
</p>

<p align="center">
  Набор утилит для анализа Windows-систем, обнаружения инжектов и проверки сетевых параметров.
</p>

<p align="center">
  <a href="https://discord.gg/residencescreenshare">
    <img alt="Discord - Residence Screenshare" src="https://img.shields.io/badge/Discord-Residence%20Screenshare-5865F2?style=for-the-badge&logo=discord&logoColor=white" />
  </a>
</p>

---

## Navigation

- [Русский](#ru)
- [English](#en)

---

<a name="ru"></a>
## Русский

### Функции

- **Dumper**
  - **Internal dumper:**
    - **Complex** — собирает все возможные данные о классах, включая путь к исходному файлу и т. д.; не рекомендуется для Lunar и подобных клиентов.
    - **Simple** — собирает только методы и поля классов.
  - **External dumper:**
    - Работает на Java 9+; рекомендуется как максимально безопасный вариант.

- **Network Scanner:** проверяет следующие ветки реестра `HKLM` на запрещённые параметры:
  - `Tcpip\Parameters\Interfaces`
  - глобальные `Tcpip\Parameters`
  - `Control\Class\{...}` сетевых адаптеров
  - `AFD\Parameters`
  - а также вывод `netsh int tcp show global` (RU/EN).

- **WinLiveInfo:** графический просмотрщик системной информации со сбором логов через PowerShell.

- **JVMTI Detector:** ищет сигнатуры JVMTI/JNI-инжектов в процессах `javaw.exe`.

  Дополнительные коды **JVMTI Detector**:
  - `code 10` — инжект не обнаружен.
  - `code 50` — возможен инжект.
  - `code 80` — 100% инжект (чит типа doomsday / troxill).

- **Found Faker:** анализирует Wi‑Fi, ARP и hosted network для обнаружения faker.

- **Bypass Finder:** ищет различные bypass-методики.

- **Launch Scripts:** ищет запуск `.bat`, `.py` и других скриптов.

- **Screenshare Tools:** набор утилит для проверки компьютера: анализ BAM, USN Journal, macros, scheduler, сервисов и многого другого.

---

<a name="en"></a>
## English

### Features

- **Dumper**
  - **Internal dumper:**
    - **Complex** — collects all possible data about classes, including the path to the source file, etc.; not recommended for Lunar and similar clients.
    - **Simple** — collects only class methods and fields.
  - **External dumper:**
    - Works on Java 9+; recommended as the safest possible option.

- **Network Scanner:** checks the following `HKLM` registry branches for prohibited parameters:
  - `Tcpip\Parameters\Interfaces`
  - global `Tcpip\Parameters`
  - `Control\Class\{...}` of network adapters
  - `AFD\Parameters`
  - as well as the output of `netsh int tcp show global` (RU/EN).

- **WinLiveInfo:** a graphical system information viewer with PowerShell log collection.

- **JVMTI Detector:** searches for JVMTI/JNI injection signatures in `javaw.exe` processes.

  Additional **JVMTI Detector** codes:
  - `code 10` — no injection detected.
  - `code 50` — possible injection.
  - `code 80` — 100% injection detected (a cheat like doomsday / troxill).

- **Found Faker:** analyzes Wi‑Fi, ARP, and hosted network data to detect faker.

- **Bypass Finder:** finds various bypass techniques.

- **Launch Scripts:** looks for the execution of `.bat`, `.py`, and other scripts.

- **Screenshare Tools:** a set of utilities for checking a computer, including analysis of BAM, USN Journal, macros, scheduler, services, and much more.
