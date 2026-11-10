"""Which perimeter alerts may auto-ban for a given response.mode."""

from __future__ import annotations

from typing import Any

FLOW_ALERT_RULES = frozenset({"flow_syn_burst", "flow_port_scan"})

_HOST_FLOOD_RULES = set(FLOW_ALERT_RULES)
_AGGRESSIVE_RULES = {
    "bruteforce_ssh",
    "honeypot_hit",
    "canary_hit",
    "egress_denylist_hit",
    "port_scan_suspected",
    *_HOST_FLOOD_RULES,
}


def derive_auto_ban_rules(
    resp_mode: str,
    auto_ban_cfg: dict[str, Any] | None = None,
    *,
    flow_auto_ban: bool = False,
) -> set[str]:
    """Return auto-ban rule ids. SYN-burst / port-scan stay alerts unless flow.auto_ban."""
    mode = str(resp_mode or "observe").strip().lower()
    cfg = dict(auto_ban_cfg or {})
    if mode == "observe":
        rules: set[str] = set()
    elif mode in ("shield", "enforce", "soft"):
        rules = {
            "bruteforce_ssh",
            "honeypot_hit",
            "canary_hit",
            *_HOST_FLOOD_RULES,
        }
    elif mode in ("aggressive", "isolate"):
        rules = set(cfg.get("rules") or []) or set(_AGGRESSIVE_RULES)
    else:
        rules = set(cfg.get("rules") or []) if cfg.get("enabled") else set()
    if not flow_auto_ban:
        rules -= FLOW_ALERT_RULES
    return rules
