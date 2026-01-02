# Windows TCP/Network Scanner (CLI)

Мини‑сканер для Windows 10/11, который проверяет сетевые настройки и выводы `netsh int tcp show global`, чтобы найти запрещённые параметры.

Что делает:
- Сканирует HKLM ветки: `Tcpip\Parameters\Interfaces`, глобальные `Tcpip\Parameters`, `Control\Class\{...}` для сетевых адаптеров, `AFD\Parameters`.
- Выполняет `netsh int tcp show global`, парсит RU/EN вывод, проверяет RSS/RSC/ECN/поставщика congestion control.

