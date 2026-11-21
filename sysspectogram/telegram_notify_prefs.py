"""Per-chat Telegram notification filters (which alerts to push).

Persisted under ``state/telegram_notify.json``. Config
``telegram.notify`` supplies defaults; runtime toggles via ``/notify`` win.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Named groups for `/notify` toggles (user-facing labels).
NOTIFY_GROUPS: dict[str, dict[str, Any]] = {
    "internet_noise": {
        "label": "Usually internet noise",
        "label_ru": "Обычный интернет-шум",
        "rules": (
            "port_scan_suspected",
            "inbound_flood_suspected",
            "flow_syn_burst",
            "flow_port_scan",
            "agent_connect_burst",
        ),
        "default_enabled": False,
    },
    "port_scans": {
        "label": "Port scans",
        "label_ru": "Сканы портов",
        "rules": ("port_scan_suspected", "flow_port_scan"),
        "default_enabled": True,
    },
    "ssh_auth": {
        "label": "SSH auth (brute / new login)",
        "label_ru": "SSH (брут / новый логин)",
        "rules": ("bruteforce_ssh", "new_login_source"),
        "default_enabled": True,
    },
    "egress_dns": {
        "label": "Egress / DNS",
        "label_ru": "Исходящие / DNS",
        "rules": ("suspicious_egress", "egress_denylist_hit", "suspicious_dns"),
        "default_enabled": True,
    },
    "host_ml": {
        "label": "Host ML anomalies",
        "label_ru": "Хост ML-аномалии",
        "rules": ("host_anomaly",),
        "patterns_off": ("mixed / subtle deviation",),
        "default_enabled": True,
    },
    "agent_ebpf": {
        "label": "Agent eBPF / path watch",
        "label_ru": "Агент eBPF / path watch",
        "rules": (
            "agent_path_watch",
            "agent_ebpf",
            "agent_ebpf_execve",
            "agent_ebpf_openat",
            "agent_open_sensitive",
        ),
        "default_enabled": False,
    },
    "agent_critical": {
        "label": "Agent critical (root / kirk / FIM)",
        "label_ru": "Агент critical (root / kirk / FIM)",
        "rules": (
            "agent_unexpected_root",
            "unexpected_root_process",
            "agent_kirk_module_hide",
            "agent_kirk_pid_hide",
            "agent_kirk_symbol_drift",
            "agent_kirk_ima_mismatch",
            "agent_kirk_agent_down",
        ),
        "prefixes": ("agent_kirk_", "agent_fim_"),
        "default_enabled": True,
    },
}

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class NotifyPrefs:
    """Runtime Telegram notify filter."""

    path: Path
    enabled: bool = True
    min_severity: str = "low"
    # group_id → enabled
    groups: dict[str, bool] = field(default_factory=dict)
    # extra explicit rule overrides (True=force on, False=force off)
    rule_overrides: dict[str, bool] = field(default_factory=dict)
    # host ML patterns to suppress (e.g. "mixed / subtle deviation")
    disable_patterns: set[str] = field(default_factory=set)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        config: dict[str, Any] | None = None,
    ) -> NotifyPrefs:
        cfg = dict(config or {})
        prefs = cls(
            path=Path(path),
            enabled=bool(cfg.get("enabled", True)),
            min_severity=str(cfg.get("min_severity") or "low").lower(),
        )
        for gid, meta in NOTIFY_GROUPS.items():
            prefs.groups[gid] = bool(meta.get("default_enabled", True))
        # Config group overrides
        for gid, val in (cfg.get("groups") or {}).items():
            if gid in NOTIFY_GROUPS:
                prefs.groups[gid] = bool(val)
        for rid, val in (cfg.get("rules") or {}).items():
            prefs.rule_overrides[str(rid)] = bool(val)
        for pat in cfg.get("disable_patterns") or []:
            prefs.disable_patterns.add(str(pat).strip().lower())
        # Always suppress subtle host noise unless user opts in
        if "mixed / subtle deviation" not in {
            p.lower() for p in (cfg.get("disable_patterns") or [])
        } and "host_ml" in prefs.groups:
            # patterns_off from group meta applied when group on via should_notify
            pass
        if prefs.path.is_file():
            try:
                data = json.loads(prefs.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            if isinstance(data, dict):
                if "enabled" in data:
                    prefs.enabled = bool(data["enabled"])
                if data.get("min_severity"):
                    prefs.min_severity = str(data["min_severity"]).lower()
                for gid, val in (data.get("groups") or {}).items():
                    if gid in NOTIFY_GROUPS:
                        prefs.groups[gid] = bool(val)
                for rid, val in (data.get("rules") or {}).items():
                    prefs.rule_overrides[str(rid)] = bool(val)
                prefs.disable_patterns = {
                    str(p).strip().lower()
                    for p in (data.get("disable_patterns") or [])
                    if str(p).strip()
                }
        return prefs

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "groups": dict(self.groups),
            "rules": dict(self.rule_overrides),
            "disable_patterns": sorted(self.disable_patterns),
            "updated_ts": time.time(),
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def set_group(self, group_id: str, on: bool) -> None:
        if group_id not in NOTIFY_GROUPS:
            raise KeyError(group_id)
        self.groups[group_id] = bool(on)
        self.save()

    def set_rule(self, rule_id: str, on: bool) -> None:
        self.rule_overrides[str(rule_id)] = bool(on)
        self.save()

    def set_master(self, on: bool) -> None:
        self.enabled = bool(on)
        self.save()

    def set_min_severity(self, severity: str) -> None:
        sev = str(severity or "low").lower()
        if sev not in _SEV_RANK:
            raise ValueError(sev)
        self.min_severity = sev
        self.save()

    def _group_allows_rule(self, rule_id: str) -> bool | None:
        """True/False if a group owns the rule; None if no group claims it."""
        rid = str(rule_id or "")
        claimed = False
        allowed = False
        for gid, meta in NOTIFY_GROUPS.items():
            rules = set(meta.get("rules") or ())
            prefixes = tuple(meta.get("prefixes") or ())
            hit = rid in rules or any(rid.startswith(p) for p in prefixes)
            if not hit:
                continue
            claimed = True
            if self.groups.get(gid, True):
                allowed = True
        if not claimed:
            return None
        return allowed

    def should_notify(
        self,
        *,
        rule_id: str,
        severity: str = "medium",
        pattern: str | None = None,
    ) -> bool:
        if not self.enabled:
            return False
        sev = str(severity or "medium").lower()
        if _SEV_RANK.get(sev, 2) < _SEV_RANK.get(self.min_severity, 1):
            # Critical always gets through min_severity floor unless master off
            if sev != "critical":
                return False
        rid = str(rule_id or "")
        if rid in self.rule_overrides:
            return bool(self.rule_overrides[rid])
        pat = (pattern or "").strip().lower()
        if pat and pat in self.disable_patterns:
            return False
        # Group patterns_off when group enabled still suppress listed patterns
        for gid, meta in NOTIFY_GROUPS.items():
            if not self.groups.get(gid, True):
                continue
            for p in meta.get("patterns_off") or ():
                if pat and pat == str(p).lower():
                    return False
        group_ok = self._group_allows_rule(rid)
        if group_ok is False:
            return False
        # Unclassified rules: allow (high-signal default)
        return True

    def summary_lines(self, *, lang: str = "en", detail: bool = False) -> list[str]:
        ru = lang.startswith("ru")
        lines = [
            f"notify={'ON' if self.enabled else 'OFF'}  min_severity={self.min_severity}",
            "",
        ]
        for gid, meta in NOTIFY_GROUPS.items():
            on = self.groups.get(gid, True)
            label = meta.get("label_ru") if ru else meta.get("label")
            mark = "✓" if on else "✗"
            lines.append(f"{mark} {gid}: {label}")
            if detail:
                rules = list(meta.get("rules") or ())
                prefixes = list(meta.get("prefixes") or ())
                if rules:
                    lines.append("    rules: " + ", ".join(rules))
                if prefixes:
                    lines.append("    prefixes: " + ", ".join(prefixes))
                pats = list(meta.get("patterns_off") or ())
                if pats:
                    lines.append("    patterns_off: " + ", ".join(pats))
        if self.rule_overrides:
            lines.append("")
            lines.append("rule overrides:")
            for rid, on in sorted(self.rule_overrides.items()):
                lines.append(f"  {'✓' if on else '✗'} {rid}")
        if self.disable_patterns:
            lines.append("patterns off: " + ", ".join(sorted(self.disable_patterns)))
        if not detail:
            tip = "полный список id: /notify ids" if ru else "full id list: /notify ids"
            lines.append("")
            lines.append(tip)
        return lines

    def ids_catalog_lines(self, *, lang: str = "en") -> list[str]:
        """Flat catalog of group ids and their rule ids for /notify ids."""
        return self.summary_lines(lang=lang, detail=True)
