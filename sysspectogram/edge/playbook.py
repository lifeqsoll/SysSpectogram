"""Playbook M — volumetric / huge L7: use Edge/CDN, not fleet IP ban theatre."""

from __future__ import annotations


def playbook_m(lang: str = "en") -> str:
    if (lang or "en").lower().startswith("ru"):
        return (
            "Playbook M — объёмный / размазанный L7\n"
            "1) Soft-ban по флоту НЕ поможет, если pipe/NIC уже забит или IP тысячи.\n"
            "2) Откройте Edge panel / `python -m sysspectogram edge status`.\n"
            "3) Если Cloudflare настроен: `edge under-attack --yes` (подтверждение обязательно).\n"
            "4) Если CDN нет: тикет провайдеру / blackhole / DNS cut; опционально Attack L2 только на жертве.\n"
            "5) После атаки: `edge clear --yes` (уровень high по умолчанию).\n"
            "См. docs/EDGE.md · docs/HOST_MITIGATION.md"
        )
    return (
        "Playbook M — volumetric / huge L7\n"
        "1) Fleet soft-ban will NOT help if the uplink/NIC is saturated or src IPs are thousands.\n"
        "2) Open Edge panel / `python -m sysspectogram edge status`.\n"
        "3) If Cloudflare is linked: `edge under-attack --yes` (confirm required).\n"
        "4) If no CDN: provider ticket / blackhole / DNS cut; optional Attack L2 on the victim only.\n"
        "5) After the wave: `edge clear --yes` (default level high).\n"
        "See docs/EDGE.md · docs/HOST_MITIGATION.md"
    )
