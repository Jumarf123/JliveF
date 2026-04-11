## Jlivef — Windows toolkit

## RU

## **Функции:**
- **Internal Dumper:** Дампит все классы запущенного javaw.exe в .txt файл.
- **Network Scanner:** проверяет HKLM ветки Tcpip\Parameters\Interfaces, глобальные Tcpip\Parameters, Control\Class\{...} сетевых адаптеров, AFD\Parameters и вывод `netsh int tcp show global` (RU/EN) на запрещённые параметры.
- **WinLiveInfo:** графический просмотрщик системной информации с PowerShell сбором логов.
- **JVMTI detector:** ищет сигнатуры JVMTI/JNI инъекций в процессах javaw.exe.

Дополнительное описание JVMTI detector:
code 10 = нет инжекта
code 50 = возможный инжект
code 80 = 100% инжект (чит по типу doomsday / troxill)

- **Found Faker:** анализ Wi‑Fi/ARP/hosted network, для обнаружения faker.
- **Bypass finder:** Ищет различные bypass методики
- **Launch scripts:** ищет запуск .bat, .py и других скриптов

## EN

- **Internal Dumper:** Dumps all classes of a running javaw.exe into a .txt file.
- **Network Scanner:** Checks HKLM branches of Tcpip\Parameters\Interfaces, global Tcpip\Parameters, Control\Class\{...} of network adapters, AFD\Parameters, and the output of `netsh int tcp show global` (RU/EN) for prohibited parameters.
- **WinLiveInfo:** A graphical system information viewer with PowerShell log collection.
- **JVMTI detector:** Searches for JVMTI/JNI injection signatures in javaw.exe processes.

Additional description of JVMTI detector:
code 10 = no injection  
code 50 = possible injection  
code 80 = 100% injection (cheat like doomsday / troxill)

- **Found Faker:** Wi‑Fi/ARP/hosted network analysis to detect faker.
- **Bypass finder:** Finds various bypass techniques.
- **Launch scripts:** Looks for execution of .bat, .py and other scripts.
