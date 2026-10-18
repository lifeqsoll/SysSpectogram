"""Plain-language text for alerts (Telegram, web, Control Center).

Each known rule gets: a short title, what happened, and what the operator should do.
Unknown rules fall back to the raw message so nothing is ever dropped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Lang = Literal["en", "ru"]


@dataclass(frozen=True)
class AlertText:
    title: str
    what: str
    action: str


def _e(title: str, what: str, action: str) -> AlertText:
    return AlertText(title, what, action)


# rule_id -> {en, ru}
RULE_TEXT: dict[str, dict[Lang, AlertText]] = {
    "agent_connect_burst": {
        "en": _e(
            "Sudden burst of network connections",
            "A process opened many outbound connections in a short time.",
            "If this is expected (build, scan, backup) — allowlist the process. "
            "Otherwise check where it connects.",
        ),
        "ru": _e(
            "Резкий всплеск сетевых соединений",
            "Процесс за короткое время открыл много исходящих соединений.",
            "Если это ожидаемая нагрузка (сборка, сканирование, backup) — добавьте процесс в исключения. "
            "Иначе посмотрите, куда он подключается.",
        ),
    },
    "agent_exec_burst": {
        "en": _e(
            "Many programs started",
            "A large number of processes started in a short window.",
            "Check whether a script or loop is running. If not — open the process list.",
        ),
        "ru": _e(
            "Множество запусков программ",
            "За короткое время запущено много процессов.",
            "Проверьте, не скрипт ли и не цикл ли это. Если нет — откройте список процессов.",
        ),
    },
    "agent_fim_change": {
        "en": _e(
            "Important system file changed",
            "File contents differ from the integrity baseline.",
            "After package updates this is normal. If you did not update — treat the file as suspicious.",
        ),
        "ru": _e(
            "Изменён важный системный файл",
            "Содержимое файла отличается от эталонного снимка (контроль целостности).",
            "После обновления пакетов это нормально. Если обновления не было — считайте файл подозрительным.",
        ),
    },
    "agent_kirk_guard_down": {
        "en": _e(
            "Guard stopped unexpectedly",
            "The protection process disappeared without a clean shutdown.",
            "Start the guard again from the app. If you stopped it yourself — ignore this.",
        ),
        "ru": _e(
            "Guard неожиданно остановился",
            "Процесс защиты исчез без штатной остановки.",
            "Запустите guard снова из приложения. Если останавливали сами — это не тревога.",
        ),
    },
    "agent_kirk_agent_down": {
        "en": _e(
            "Agent not responding",
            "The integrity agent stopped sending heartbeats.",
            "On Home press Start protection. If it keeps failing, check state/agent.stderr.log.",
        ),
        "ru": _e(
            "Агент не отвечает",
            "Агент целостности перестал присылать сигналы (heartbeat).",
            "На Главной нажмите «Включить защиту». Если снова падает — смотрите state/agent.stderr.log.",
        ),
    },
    "agent_start_failed": {
        "en": _e(
            "Agent failed to start",
            "The guard could not launch the integrity agent.",
            "Check that the agent binary exists and Start protection again.",
        ),
        "ru": _e(
            "Агент не запустился",
            "Guard не смог запустить агент целостности.",
            "Проверьте, что бинарник агента на месте, и снова нажмите «Включить защиту».",
        ),
    },
    "agent_path_watch": {
        "en": _e(
            "Access to a watched path",
            "A process touched a directory or file on the watch list.",
            "Check who accessed it. For your own services, add an exception.",
        ),
        "ru": _e(
            "Доступ к защищаемому пути",
            "Процесс обратился к каталогу или файлу из списка наблюдения.",
            "Проверьте, кто обращается. Для своих сервисов добавьте исключение.",
        ),
    },
    "agent_module_load": {
        "en": _e(
            "Kernel module loaded",
            "A new module was loaded into the kernel.",
            "If you did not install a driver — inspect the module with modinfo and the journal.",
        ),
        "ru": _e(
            "Загружен модуль ядра",
            "В ядро загружен новый модуль.",
            "Если вы не ставили драйвер — проверьте модуль через modinfo и журнал.",
        ),
    },
    "agent_unexpected_root": {
        "en": _e(
            "Unexpected root privileges",
            "A process escalated to root without an allow rule.",
            "Inspect the process and its parent. When in doubt, stop the process.",
        ),
        "ru": _e(
            "Неожиданное получение прав root",
            "Процесс без разрешения поднял права до root.",
            "Проверьте процесс и его родителя. Это важный сигнал: при сомнении остановите процесс.",
        ),
    },
    "agent_ebpf_execve": {
        "en": _e(
            "Program start (eBPF)",
            "The kernel recorded a program start matching an eBPF rule.",
            "Check the path and parent process.",
        ),
        "ru": _e(
            "Запуск программы (eBPF)",
            "Ядро зафиксировало запуск программы по правилу eBPF.",
            "Проверьте путь и родительский процесс.",
        ),
    },
    "bruteforce_ssh": {
        "en": _e(
            "SSH brute-force",
            "Many failed SSH logins from the same address in a short time.",
            "Ban the IP if it is not you. Prefer keys over passwords and limit open SSH.",
        ),
        "ru": _e(
            "Брутфорс SSH",
            "Много неудачных попыток входа по SSH с одного адреса за короткое время.",
            "Заблокируйте IP, если это не вы. Лучше ключи вместо пароля и ограничить доступ к SSH.",
        ),
    },
    "port_scan_suspected": {
        "en": _e(
            "Possible port scan",
            "Many different external addresses hit the same port.",
            "Usually internet noise. Ban persistent scanners; keep unused ports closed.",
        ),
        "ru": _e(
            "Похоже на сканирование портов",
            "Много разных внешних адресов стучатся в один порт.",
            "Часто это шум из интернета. Баньте настойчивых сканеров; закрывайте лишние порты.",
        ),
    },
    "new_login_source": {
        "en": _e(
            "Login from a new address",
            "Successful login from an IP you have not seen before.",
            "Confirm it is you or an expected admin. If not — change keys/passwords and ban the IP.",
        ),
        "ru": _e(
            "Вход с нового адреса",
            "Успешный вход с IP, которого раньше не было.",
            "Убедитесь, что это вы или ожидаемый админ. Если нет — смените ключи/пароли и заблокируйте IP.",
        ),
    },
    "egress_denylist_hit": {
        "en": _e(
            "Outbound to a blocked address",
            "This host opened a connection to a denylisted destination.",
            "Possible malware beacon. Inspect the process and ban or kill if unknown.",
        ),
        "ru": _e(
            "Исходящее к заблокированному адресу",
            "Хост открыл соединение с адресом из чёрного списка.",
            "Возможен маяк вредоноса. Проверьте процесс; неизвестный — остановите и заблокируйте.",
        ),
    },
    "suspicious_egress": {
        "en": _e(
            "Unusual outbound connection",
            "New external egress that does not match the baseline.",
            "Check which process opened it. Allowlist if expected; investigate if not.",
        ),
        "ru": _e(
            "Необычное исходящее соединение",
            "Новый внешний выход, не похожий на обычный для этого хоста.",
            "Проверьте процесс. Если ожидаемо — в исключения; если нет — разберитесь.",
        ),
    },
    "suspicious_dns": {
        "en": _e(
            "Suspicious DNS lookup",
            "DNS query for a denylisted or suspicious domain.",
            "Possible malware callback. Check the process that resolved it.",
        ),
        "ru": _e(
            "Подозрительный DNS-запрос",
            "Запрос имени из чёрного списка или подозрительного домена.",
            "Возможен callback вредоноса. Проверьте процесс, который делал запрос.",
        ),
    },
    "honeypot_hit": {
        "en": _e(
            "Honeypot touched",
            "Something connected to a honeypot port.",
            "Almost never legitimate. Ban the source IP.",
        ),
        "ru": _e(
            "Сработали honeypot",
            "Кто-то подключился к honeypot-порту.",
            "Почти никогда не бывает своим. Заблокируйте IP.",
        ),
    },
    "canary_hit": {
        "en": _e(
            "Canary port hit",
            "Something connected to a canary listening port.",
            "Treat as hostile reconnaissance. Ban the source.",
        ),
        "ru": _e(
            "Сработали canary-порт",
            "Подключение к canary-порту.",
            "Считайте разведкой. Заблокируйте источник.",
        ),
    },
    "lockdown_inbound": {
        "en": _e(
            "Inbound during lockdown",
            "Host is in lockdown; inbound traffic is treated as hostile.",
            "Allowlist your admin IP or lift lockdown when safe.",
        ),
        "ru": _e(
            "Входящее во время lockdown",
            "Хост в lockdown; входящий трафик считается враждебным.",
            "Добавьте свой IP в allowlist или снимите lockdown, когда безопасно.",
        ),
    },
    "host_anomaly": {
        "en": _e(
            "Looks like a miner / runaway load",
            "Host metrics look like sustained high CPU or GPU use, often miner-like.",
            "Check top processes. Stop unknown heavy jobs; keep expected builds allowlisted.",
        ),
        "ru": _e(
            "Похоже на майнер / перегрузку",
            "Метрики хоста похожи на длительную высокую нагрузку CPU или GPU — часто как у майнера.",
            "Проверьте топ процессов. Неизвестную нагрузку остановите; ожидаемые сборки — в исключения.",
        ),
    },
}

_FALLBACK: dict[Lang, AlertText] = {
    "en": _e(
        "Alert",
        "A rule fired without extra detail.",
        "Open the alert log and inspect the event.",
    ),
    "ru": _e(
        "Алерт",
        "Правило сработало без подробностей.",
        "Откройте журнал алертов и проверьте событие.",
    ),
}


def describe(rule_id: str, message: str = "", *, lang: Lang = "ru") -> AlertText:
    lang = "en" if lang == "en" else "ru"
    known = RULE_TEXT.get(rule_id)
    if known is not None:
        return known[lang]
    fb = _FALLBACK[lang]
    if message:
        return AlertText(
            title=rule_id.replace("_", " ") or fb.title,
            what=message,
            action=fb.action,
        )
    return AlertText(
        title=rule_id.replace("_", " ") or fb.title,
        what=fb.what,
        action=fb.action,
    )


def is_unattributed(pid: int | None) -> bool:
    """A network/exec event with no process attribution (pid 0 or missing)."""
    return not pid or int(pid) <= 0
