Internal JVM Class Dumper + Network Scanner (Windows 10/11)

Что внутри:
- Internal Dumper: дампит все загруженные классы 

- Network Scanner:проверяет HKLM ветки Tcpip\Parameters\Interfaces, глобальные Tcpip\Parameters, Control\Class\{...} сетевых адаптеров, AFD\Parameters и парсит `netsh int tcp show global` (RU/EN) на запрещённые параметры.

