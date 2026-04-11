# Jlivef — Windows toolkit

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

- **Internal Dumper:** Дампит все классы запущенного `javaw.exe` в `.txt` файл.
- **Network Scanner:** Проверяет ветки реестра `HKLM`:
  - `Tcpip\Parameters\Interfaces`
  - глобальные `Tcpip\Parameters`
  - `Control\Class\{...}` сетевых адаптеров
  - `AFD\Parameters`
  - а также вывод `netsh int tcp show global` (RU/EN) на запрещённые параметры.
- **WinLiveInfo:** Графический просмотрщик системной информации со сбором логов через PowerShell.
- **JVMTI detector:** Ищет сигнатуры JVMTI/JNI инъекций в процессах `javaw.exe`.

  Дополнительное описание JVMTI detector:
  - `code 10` = нет инжекта
  - `code 50` = возможный инжект
  - `code 80` = 100% инжект (чит типа doomsday / troxill)

- **Found Faker:** Анализ Wi‑Fi/ARP/hosted network для обнаружения faker.
- **Bypass finder:** Ищет различные bypass-методики.
- **Launch scripts:** Ищет запуск `.bat`, `.py` и других скриптов.

---

<a name="en"></a>
## English

### Features

- **Internal Dumper:** Dumps all classes of a running `javaw.exe` into a `.txt` file.
- **Network Scanner:** Checks the following HKLM registry branches for prohibited parameters:
  - `Tcpip\Parameters\Interfaces`
  - global `Tcpip\Parameters`
  - `Control\Class\{...}` of network adapters
  - `AFD\Parameters`
  - as well as the output of `netsh int tcp show global` (RU/EN).
- **WinLiveInfo:** A graphical system information viewer with PowerShell log collection.
- **JVMTI detector:** Searches for JVMTI/JNI injection signatures in `javaw.exe` processes.

  Additional JVMTI detector codes:
  - `code 10` = no injection
  - `code 50` = possible injection
  - `code 80` = 100% injection (cheat like doomsday / troxill)

- **Found Faker:** Wi‑Fi/ARP/hosted network analysis to detect faker.
- **Bypass finder:** Finds various bypass techniques.
- **Launch scripts:** Looks for execution of `.bat`, `.py` and other scripts.
