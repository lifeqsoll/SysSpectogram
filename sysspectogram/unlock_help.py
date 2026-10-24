"""Plain-language instructions when a host control plane is LOCKED."""

from __future__ import annotations


def locked_playbook(*, host_id: str = "this host", lang: str = "en") -> str:
    """Detailed what-to-do when Kill/Attack/lockdown need unlock."""
    hid = host_id or "this host"
    if str(lang).lower() == "ru":
        return (
            f"Хост {hid} в состоянии LOCKED — опасные действия заблокированы.\n"
            "\n"
            "Что это значит:\n"
            "• Статус и графики можно смотреть.\n"
            "• Kill / Attack / lockdown / ban требуют unlock.\n"
            "\n"
            "Что сделать сейчас (выберите один способ):\n"
            f"1) Быстро для ОДНОГО хоста: откройте Telegram-бота {hid} → "
            "возьмите код на этой VPS (Control Center → Show code, или по SSH: "
            "cat state/unlock.code) → отправьте /unlock КОД в бота ЭТОЙ машины.\n"
            "2) Много хостов: Control Center → Fleet → Unlock locked hosts.\n"
            "3) Без CC: SSH на VPS → menu / cat state/unlock.code → "
            "/unlock в боте этой VPS.\n"
            "\n"
            "Потом повторите Attack / Kill.\n"
            "Пока LOCKED: смотрите /charts; если уже включён shield — мягкий авто-бан IP "
            "может работать; при пожаре без unlock — firewall у провайдера."
        )
    return (
        f"Host {hid} is LOCKED — control actions blocked.\n"
        "\n"
        "What this means:\n"
        "• Status/charts still work.\n"
        "• Kill / Attack / lockdown / ban need unlock.\n"
        "\n"
        "What to do now (pick one):\n"
        f"1) Fastest for ONE host: open the Telegram bot for {hid} → get the code on "
        "that VPS (Control Center → Show code, or SSH: cat state/unlock.code) → "
        "send /unlock CODE in THAT host’s bot.\n"
        "2) Many hosts: Control Center → Fleet → Unlock locked hosts.\n"
        "3) No CC: SSH to the VPS → menu / cat state/unlock.code → "
        "/unlock in that VPS bot.\n"
        "\n"
        "Then retry Attack / Kill.\n"
        "While locked: watch /charts; if shield is already on, soft IP auto-ban may "
        "still run; if the box is on fire and unlock is impossible — use the provider firewall."
    )
