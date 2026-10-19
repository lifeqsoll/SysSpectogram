"""Zapret-like interactive menu for headless VPS (SSH). Rich prompts, EN/RU."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from sysspectogram.config import load_config, state_root, user_settings_path
from sysspectogram.protect_service import (
    disable_and_stop,
    install_and_enable,
    restart as protect_restart,
    start as protect_start,
    status as protect_status,
    stop as protect_stop,
)

console = Console()


def _lang() -> str:
    try:
        cfg = load_config()
        lang = str((cfg.get("ui") or {}).get("lang") or "en").lower()
        return lang if lang in ("en", "ru") else "en"
    except Exception:
        return "en"


def _t(en: str, ru: str) -> str:
    return ru if _lang() == "ru" else en


def _write_overlay(changes: dict[str, Any]) -> None:
    path = user_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cur: dict[str, Any] = {}
    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                cur = raw
        except json.JSONDecodeError:
            cur = {}
    for k, v in changes.items():
        if isinstance(v, (bool, int, float, str)):
            cur[k] = v
        elif isinstance(v, list):
            cur[k] = ", ".join(str(x) for x in v)
    path.write_text(json.dumps(cur, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _preflight() -> list[tuple[bool, str]]:
    checks: list[tuple[bool, str]] = []
    py = shutil.which("python3")
    checks.append((bool(py), _t("python3 on PATH", "python3 в PATH")))
    venv_ok = False
    if py:
        r = subprocess.run(
            [py, "-c", "import venv"],
            capture_output=True,
            check=False,
        )
        venv_ok = r.returncode == 0
    checks.append((venv_ok, _t("python3 venv module", "модуль venv")))
    home = state_root()
    checks.append((True, f"SYSSPECTOGRAM_HOME={home}"))
    import_ok = False
    try:
        import sysspectogram  # noqa: F401

        import_ok = True
    except Exception:
        import_ok = False
    checks.append((import_ok, _t("sysspectogram importable", "пакет sysspectogram импортируется")))
    ms = bool(shutil.which("minisign"))
    checks.append(
        (
            ms,
            _t(
                "minisign (optional for verify)",
                "minisign (опционально для подписи)",
            ),
        )
    )
    return checks


def _show_preflight() -> None:
    table = Table(title=_t("Preflight", "Проверка"))
    table.add_column("ok")
    table.add_column("check")
    for ok, label in _preflight():
        table.add_row("✓" if ok else "✗", label)
    console.print(table)
    if not all(ok for ok, _ in _preflight() if "optional" not in _.lower() and "опционально" not in _.lower()):
        console.print(
            Panel(
                _t(
                    "Debian/Ubuntu: sudo apt install python3 python3-venv minisign\n"
                    "Arch: sudo pacman -S python python-virtualenv minisign\n"
                    "Fedora: sudo dnf install python3 python3-virtualenv minisign",
                    "Debian/Ubuntu: sudo apt install python3 python3-venv minisign\n"
                    "Arch: sudo pacman -S python python-virtualenv minisign\n"
                    "Fedora: sudo dnf install python3 python3-virtualenv minisign",
                ),
                title=_t("Install deps", "Пакеты"),
            )
        )


def _cmd_status() -> None:
    st = protect_status()
    console.print(
        Panel(
            f"home={st['home']}\n"
            f"service installed={st['installed']} enabled={st['enabled']} active={st['active']}\n"
            f"detail={st.get('detail') or '-'}",
            title=_t("Protect service", "Служба защиты"),
        )
    )
    try:
        cfg = load_config()
        mode = (cfg.get("response") or {}).get("mode", "observe")
        never = (cfg.get("response") or {}).get("never_ban_cidrs") or []
        console.print(f"mode={mode}  never_ban={never or '-'}")
    except Exception as exc:
        console.print(f"[yellow]config[/] {exc}")


def _cmd_service() -> None:
    console.print(
        _t(
            "1) enable+start  2) start  3) stop  4) restart  5) disable  0) back",
            "1) включить+старт  2) старт  3) стоп  4) рестарт  5) выключить  0) назад",
        )
    )
    choice = Prompt.ask(">", choices=["0", "1", "2", "3", "4", "5"], default="0")
    actions = {
        "1": install_and_enable,
        "2": protect_start,
        "3": protect_stop,
        "4": protect_restart,
        "5": disable_and_stop,
    }
    fn = actions.get(choice)
    if not fn:
        return
    res = fn()
    console.print(res)


def _cmd_mode() -> None:
    mode = Prompt.ask(
        _t("Mode", "Режим"),
        choices=["observe", "shield", "aggressive", "isolate"],
        default="observe",
    )
    if mode != "observe":
        cfg = load_config()
        never = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
        if not never:
            console.print(
                "[red]"
                + _t(
                    "Set never-ban IPs first (menu → Never-ban), or confirm override.",
                    "Сначала задайте never-ban IP (меню → Never-ban), или подтвердите обход.",
                )
                + "[/]"
            )
            if not Confirm.ask(_t("Continue anyway?", "Всё равно продолжить?"), default=False):
                return
    _write_overlay({"response.mode": mode})
    console.print(f"[green]response.mode={mode}[/] — restart protect service to apply")


def _cmd_never_ban() -> None:
    cfg = load_config()
    cur = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    console.print(_t("Current:", "Сейчас:"), ", ".join(cur) if cur else "(empty)")
    console.print(
        _t(
            "Enter IPs/CIDRs comma or space separated. Bare IP → /32.",
            "IP/CIDR через запятую или пробел. Голый IP → /32.",
        )
    )
    raw = Prompt.ask(_t("Never-ban", "Never-ban"), default=", ".join(cur))
    _write_overlay({"response.never_ban_cidrs": raw})
    console.print("[green]saved[/]")


def _cmd_telegram() -> None:
    token = Prompt.ask("TELEGRAM_BOT_TOKEN", default="", password=True)
    chat = Prompt.ask("TELEGRAM_CHAT_ID", default="")
    env_path = state_root() / ".env"
    lines: dict[str, str] = {}
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, _, v = line.partition("=")
                lines[k.strip()] = v.strip()
    if token:
        lines["TELEGRAM_BOT_TOKEN"] = token
    if chat:
        lines["TELEGRAM_CHAT_ID"] = chat
    env_path.write_text("\n".join(f"{k}={v}" for k, v in lines.items()) + "\n", encoding="utf-8")
    os.chmod(env_path, 0o600)
    _write_overlay({"telegram.enabled": True})
    console.print(f"[green]wrote {env_path}[/]")


def _cmd_unlock() -> None:
    code_path = state_root() / "state" / "unlock.code"
    if code_path.is_file():
        console.print(Panel(code_path.read_text(encoding="utf-8").strip(), title="unlock.code"))
    else:
        console.print(
            _t(
                "No unlock.code — start protect / guard first.",
                "Нет unlock.code — сначала запустите protect / guard.",
            )
        )


def _cmd_checklist() -> None:
    cfg = load_config()
    never = list((cfg.get("response") or {}).get("never_ban_cidrs") or [])
    tg = bool((cfg.get("telegram") or {}).get("enabled"))
    mode = str((cfg.get("response") or {}).get("mode") or "observe")
    st = protect_status()
    import_ok = False
    try:
        import sysspectogram  # noqa: F401

        import_ok = True
    except Exception:
        import_ok = False
    rows = [
        (_t("never-ban set", "never-ban задан"), bool(never)),
        (_t("telegram enabled", "telegram включён"), tg),
        (_t("mode not observe (if you wanted auto-ban)", "режим не observe"), mode != "observe"),
        (_t("protect service active", "служба protect active"), bool(st.get("active"))),
        (_t("stack importable", "стек импортируется"), import_ok),
    ]
    table = Table(title=_t("Checklist", "Чеклист"))
    table.add_column("ok")
    table.add_column("item")
    for label, ok in rows:
        table.add_row("✓" if ok else "…", label)
    console.print(table)


def _cmd_update() -> None:
    _show_preflight()
    tag = Prompt.ask(_t("Release tag", "Тег релиза"), default="v1.1.1")
    if Confirm.ask(_t("Download & install now?", "Скачать и установить сейчас?"), default=True):
        try:
            from sysspectogram.friend_update import update_stack

            res = update_stack(tag)
            console.print(res)
            if res.get("ok") and Confirm.ask(
                _t("Restart protect service?", "Перезапустить службу?"), default=True
            ):
                console.print(protect_restart())
        except Exception as exc:
            console.print(f"[red]{exc}[/]")


def _cmd_configure() -> None:
    from sysspectogram.configure_tui import run_configure
    from sysspectogram.config import ROOT

    run_configure(
        config_path=ROOT / "configs" / "default.yaml",
        interactive=True,
    )


def run_menu() -> int:
    console.print(
        Panel(
            _t(
                "SysSpectogram friend menu (SSH / VPS). Arrow-free: type a number.",
                "Меню SysSpectogram для VPS по SSH. Вводите номер пункта.",
            ),
            title="SysSpectogram",
        )
    )
    while True:
        console.print()
        items = [
            ("1", _t("Status / health", "Статус / health")),
            ("2", _t("Protect service (systemd --user)", "Служба защиты (systemd --user)")),
            ("3", _t("Protection mode", "Режим защиты")),
            ("4", _t("Never-ban IPs", "Never-ban IP")),
            ("5", _t("Telegram .env", "Telegram .env")),
            ("6", _t("Show unlock code", "Показать unlock-код")),
            ("7", _t("Checklist", "Чеклист")),
            ("8", _t("Update stack", "Обновить стек")),
            ("9", _t("Advanced configure", "Расширенный configure")),
            ("0", _t("Quit", "Выход")),
        ]
        for k, label in items:
            console.print(f"  [cyan]{k}[/]  {label}")
        choice = Prompt.ask(">", choices=[k for k, _ in items], default="0")
        if choice == "0":
            return 0
        {
            "1": _cmd_status,
            "2": _cmd_service,
            "3": _cmd_mode,
            "4": _cmd_never_ban,
            "5": _cmd_telegram,
            "6": _cmd_unlock,
            "7": _cmd_checklist,
            "8": _cmd_update,
            "9": _cmd_configure,
        }[choice]()
