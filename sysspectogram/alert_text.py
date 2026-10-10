"""Plain-language text for alerts (Telegram and Control Center).

Each known rule gets: a short title, what happened, and what the operator should do.
Unknown rules fall back to the raw message so nothing is ever dropped.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AlertText:
    title: str
    what: str
    action: str


RULE_TEXT: dict[str, AlertText] = {
    "agent_connect_burst": AlertText(
        "Резкий всплеск сетевых соединений",
        "Процесс за короткое время открыл много исходящих соединений.",
        "Если это ожидаемая нагрузка (сборка, сканирование, backup) — добавьте процесс в исключения. "
        "Иначе посмотрите, куда он подключается.",
    ),
    "agent_exec_burst": AlertText(
        "Множество запусков программ",
        "За короткое время запущено много процессов.",
        "Проверьте, не скрипт ли и не цикл ли это. Если нет — откройте список процессов.",
    ),
    "agent_fim_change": AlertText(
        "Изменён важный системный файл",
        "Содержимое файла отличается от эталонного снимка (контроль целостности).",
        "После обновления пакетов это нормально: проверьте `pacman -Qkk <пакет>`. "
        "Если обновления не было — считайте файл подозрительным.",
    ),
    "agent_kirk_guard_down": AlertText(
        "Guard неожиданно остановился",
        "Процесс защиты исчез без штатной остановки.",
        "Запустите guard снова из приложения. Если останавливали сами — это не тревога.",
    ),
    "agent_path_watch": AlertText(
        "Доступ к защищаемому пути",
        "Процесс обратился к каталогу или файлу из списка наблюдения.",
        "Проверьте, кто обращается. Для своих сервисов добавьте исключение.",
    ),
    "agent_module_load": AlertText(
        "Загружен модуль ядра",
        "В ядро загружен новый модуль.",
        "Если вы не ставили драйвер — проверьте модуль через `modinfo` и журнал.",
    ),
    "agent_unexpected_root": AlertText(
        "Неожиданное получение прав root",
        "Процесс без разрешения поднял права до root.",
        "Проверьте процесс и его родителя. Это важный сигнал: при сомнении остановите процесс.",
    ),
    "agent_ebpf_execve": AlertText(
        "Запуск программы (eBPF)",
        "Ядро зафиксировало запуск программы по правилу eBPF.",
        "Проверьте путь и родительский процесс.",
    ),
}


def describe(rule_id: str, message: str = "") -> AlertText:
    known = RULE_TEXT.get(rule_id)
    if known is not None:
        return known
    return AlertText(
        title=rule_id.replace("_", " ") or "Алерт",
        what=message or "Правило сработало без подробностей.",
        action="Откройте журнал алертов и проверьте событие.",
    )


def is_unattributed(pid: int | None) -> bool:
    """A network/exec event with no process attribution (pid 0 or missing)."""
    return not pid or int(pid) <= 0
