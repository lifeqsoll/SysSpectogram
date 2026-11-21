"""Per-rule noise memory. An EWMA of false positives nudges severity.

Critical is never softened.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

_RANK = ("info", "low", "medium", "high", "critical")
_BASE_THRESHOLD = 0.5
_FP_TARGET = 0.85
_SOFTEN_AT = 0.55


class RuleThresholdStore:
    def __init__(
        self,
        path: str | Path,
        *,
        alpha: float = 0.3,
        enabled: bool = True,
        save_interval_sec: float = 5.0,
    ) -> None:
        self.path = Path(path)
        self.alpha = float(alpha)
        if not 0.0 < self.alpha <= 1.0:
            self.alpha = 0.3
        self.enabled = bool(enabled)
        self.save_interval_sec = max(0.5, float(save_interval_sec))
        self.rules: dict[str, dict] = {}
        self._dirty = False
        self._last_save = 0.0
        if self.enabled:
            self._load()

    def record_hit(self, rule_id: str, severity: str = "") -> None:
        if not self.enabled:
            return
        row = self._row(rule_id)
        sev = (severity or "").strip().lower()
        if sev and not row.get("base_severity"):
            row["base_severity"] = sev
        row["hits"] = int(row.get("hits") or 0) + 1
        prev = float(row.get("ewma") or 0.0)
        row["ewma"] = (1.0 - self.alpha) * prev
        thr = float(row.get("threshold") if row.get("threshold") is not None else _BASE_THRESHOLD)
        row["threshold"] = (1.0 - self.alpha) * thr + self.alpha * _BASE_THRESHOLD
        self._mark_dirty()

    def record_fp(self, rule_id: str) -> None:
        if not self.enabled:
            return
        row = self._row(rule_id)
        row["fps"] = int(row.get("fps") or 0) + 1
        prev = float(row.get("ewma") or 0.0)
        row["ewma"] = self.alpha * 1.0 + (1.0 - self.alpha) * prev
        thr = float(row.get("threshold") if row.get("threshold") is not None else _BASE_THRESHOLD)
        row["threshold"] = (1.0 - self.alpha) * thr + self.alpha * _FP_TARGET
        self._mark_dirty()

    def flush(self) -> None:
        if self._dirty:
            self._save()

    def effective_severity_adjust(self, rule_id: str, severity: str) -> str:
        """Step severity down one rank when the FP EWMA is hot. Never softens critical."""
        raw = (severity or "").strip()
        sev = raw.lower()
        if sev == "critical":
            return "critical"
        if sev not in _RANK:
            return raw or severity
        if not self.enabled:
            return sev
        row = self.rules.get(rule_id) or {}
        try:
            ewma = float(row.get("ewma") or 0.0)
        except (TypeError, ValueError):
            ewma = 0.0
        idx = _RANK.index(sev)
        if ewma >= _SOFTEN_AT and idx > 0:
            return _RANK[idx - 1]
        return sev

    def _row(self, rule_id: str) -> dict:
        key = str(rule_id or "alert")
        row = self.rules.get(key)
        if row is None:
            row = {
                "ewma": 0.0,
                "hits": 0,
                "fps": 0,
                "threshold": _BASE_THRESHOLD,
                "base_severity": "",
            }
            self.rules[key] = row
        return row

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        rules = payload.get("rules") if isinstance(payload, dict) else None
        if isinstance(rules, dict):
            self.rules = {str(k): dict(v) for k, v in rules.items() if isinstance(v, dict)}

    def _mark_dirty(self) -> None:
        self._dirty = True
        now = time.monotonic()
        if now - self._last_save >= self.save_interval_sec:
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"alpha": self.alpha, "rules": self.rules}
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._dirty = False
        self._last_save = time.monotonic()
