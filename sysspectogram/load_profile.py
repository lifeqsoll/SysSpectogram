"""VPS load presets: lite (small VPS) vs full (large VDS)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

# Approximate budgets (idle overhead target):
#   lite  — ~1–3% of 1 vCPU, <80–150 MiB RSS combined guard+agent
#   full  — more polling / FIM / eBPF / metrics; fine on 4+ vCPU VDS

PRESETS: dict[str, dict[str, Any]] = {
    "lite": {
        "collector": {
            "interval_sec": 2.0,
            "max_cores": 8,
            "socket_sample_every": 10,
        },
        "monitor": {
            "interval_sec": 10.0,
            "cooldown_sec": 120.0,
            "top_processes": 3,
        },
        "perimeter": {
            "poll_sec": 4.0,
        },
        "recon": {
            "auto": False,
            "nmap": False,
        },
        "agent": {
            "metrics": True,
            "metrics_ms": 2000,
            "cooldown_sec": 180,
            "max_alerts_per_min": 10,
            "poll_ms": 1000,
            "mode": "userspace",
            "fim": {"enabled": False, "interval_sec": 120, "paths": []},
        },
        "ensemble": {
            "host_weight": 0.7,
            "agent_weight": 0.3,
        },
        "flow": {
            "enabled": False,
            "window_sec": 60,
            "syn_threshold": 120,
            "unique_port_threshold": 60,
        },
    },
    "full": {
        "collector": {
            "interval_sec": 1.0,
            "max_cores": 32,
            "socket_sample_every": 5,
        },
        "monitor": {
            "interval_sec": 5.0,
            "cooldown_sec": 45.0,
            "top_processes": 5,
        },
        "perimeter": {
            "poll_sec": 1.5,
        },
        "recon": {
            "auto": False,
            "nmap": False,
        },
        "agent": {
            "metrics": True,
            "metrics_ms": 1000,
            "cooldown_sec": 60,
            "max_alerts_per_min": 40,
            "poll_ms": 400,
            "mode": "userspace",
            "fim": {
                "enabled": True,
                "interval_sec": 30,
                "paths": [
                    "/usr/bin/sshd",
                    "/usr/sbin/sshd",
                    "/etc/passwd",
                    "/etc/shadow",
                    "/etc/sudoers",
                ],
            },
        },
        "ensemble": {
            "host_weight": 0.55,
            "agent_weight": 0.45,
        },
        "flow": {
            "enabled": True,
            "window_sec": 30,
            "syn_threshold": 80,
            "unique_port_threshold": 40,
        },
    },
}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def apply_load_profile(cfg: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    """Merge preset under explicit YAML keys (YAML wins over preset)."""
    profile = (name or cfg.get("load_profile") or "lite").strip().lower()
    if profile in {"vds", "large", "heavy"}:
        profile = "full"
    if profile in {"small", "vps", "low"}:
        profile = "lite"
    preset = PRESETS.get(profile)
    if not preset:
        cfg["load_profile"] = profile
        return cfg
    # Preset first, then user config overlays (user wins)
    merged = _deep_merge({"load_profile": profile}, preset)
    return _deep_merge(merged, cfg)
