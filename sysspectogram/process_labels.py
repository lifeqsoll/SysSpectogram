"""Operator process label rules — VPS-first FP control without retraining CNN.

Replaces / extends OperatorFeedback with match kinds: exact, prefix, glob, regex.
"""

from __future__ import annotations

import fnmatch
import json
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Label = Literal["ignore", "baseline", "anomaly"]
MatchKind = Literal[
    "exact",
    "comm_prefix",
    "comm_regex",
    "path_glob",
    "path_contains",
    "cmdline_contains",
    "rule_id",
]

_LABEL_PRIORITY = {"anomaly": 3, "ignore": 2, "baseline": 1}


@dataclass
class ProcessLabelRule:
    id: str
    label: Label
    match: MatchKind
    pattern: str
    source: str = "tg"
    note: str = ""
    path: str = ""
    rule_id: str = ""
    ts: float = field(default_factory=time.time)
    expires_at: float | None = None

    def expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return float(now or time.time()) >= float(self.expires_at)

    # OperatorFeedback / Telegram back-compat
    @property
    def key(self) -> str:
        return self.pattern

    @property
    def kind(self) -> str:
        return self.label


def process_key(*, comm: str | None = None, path: str | None = None, name: str | None = None) -> str:
    """Stable key for a process identity (prefer basename of path, else comm/name)."""
    if path:
        base = Path(path).name.strip()
        if base and base not in (".", "/"):
            return base.lower()
    for raw in (comm, name):
        if raw:
            s = str(raw).strip().lower()
            if s:
                return s
    return ""


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def _rule_matches(
    rule: ProcessLabelRule,
    *,
    comm: str,
    path: str,
    cmdline: str,
    alert_rule_id: str = "",
) -> bool:
    pat = rule.pattern
    kind = rule.match
    if kind == "rule_id":
        return bool(alert_rule_id) and alert_rule_id == pat
    if kind == "exact":
        key = process_key(comm=comm or None, path=path or None)
        return bool(key) and key == pat.lower()
    if kind == "comm_prefix":
        c = _norm(comm)
        p = pat.lower()
        return bool(c) and (c == p or c.startswith(p))
    if kind == "comm_regex":
        try:
            return bool(re.search(pat, comm or "", re.IGNORECASE))
        except re.error:
            return False
    if kind == "path_glob":
        return bool(path) and fnmatch.fnmatch(path, pat)
    if kind == "path_contains":
        return bool(path) and pat.lower() in path.lower()
    if kind == "cmdline_contains":
        return bool(cmdline) and pat.lower() in cmdline.lower()
    return False


class ProcessLabelStore:
    """Persisted process memories used to mute FP and boost known-bad shapes."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.rules: list[ProcessLabelRule] = []
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            # migrate legacy operator_feedback.json beside us
            legacy = self.path.parent / "operator_feedback.json"
            if legacy.exists():
                self._migrate_v1(legacy)
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        schema = str(data.get("schema") or "")
        if "operator_feedback.v1" in schema or "entries" in data:
            self._load_v1_entries(data.get("entries") or [])
            return
        rows = data.get("rules") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return
        out: list[ProcessLabelRule] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            label = str(row.get("label") or row.get("kind") or "")
            match = str(row.get("match") or "exact")
            pattern = str(row.get("pattern") or row.get("key") or "").strip()
            if label not in ("ignore", "baseline", "anomaly") or not pattern:
                continue
            if match not in (
                "exact",
                "comm_prefix",
                "comm_regex",
                "path_glob",
                "path_contains",
                "cmdline_contains",
                "rule_id",
            ):
                match = "exact"
            out.append(
                ProcessLabelRule(
                    id=str(row.get("id") or uuid.uuid4().hex[:12]),
                    label=label,  # type: ignore[arg-type]
                    match=match,  # type: ignore[arg-type]
                    pattern=pattern,
                    source=str(row.get("source") or "import"),
                    note=str(row.get("note") or "")[:200],
                    path=str(row.get("path") or "")[:512],
                    rule_id=str(row.get("rule_id") or ""),
                    ts=float(row.get("ts") or time.time()),
                    expires_at=(
                        float(row["expires_at"]) if row.get("expires_at") is not None else None
                    ),
                )
            )
        self.rules = out

    def _load_v1_entries(self, rows: list) -> None:
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "").strip().lower()
            kind = str(row.get("kind") or "")
            if not key or kind not in ("ignore", "baseline", "anomaly"):
                continue
            self.rules.append(
                ProcessLabelRule(
                    id=uuid.uuid4().hex[:12],
                    label=kind,  # type: ignore[arg-type]
                    match="exact",
                    pattern=key,
                    source="migrate",
                    note=str(row.get("note") or "")[:200],
                    path=str(row.get("path") or "")[:512],
                    rule_id=str(row.get("rule_id") or ""),
                    ts=float(row.get("ts") or time.time()),
                )
            )

    def _migrate_v1(self, legacy: Path) -> None:
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self._load_v1_entries(data.get("entries") or [])
        if self.rules:
            self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "sysspectogram.process_labels.v2",
            "rules": [asdict(r) for r in self.rules],
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def add_rule(self, rule: ProcessLabelRule) -> ProcessLabelRule:
        with self._lock:
            # replace same match+pattern
            self.rules = [
                r
                for r in self.rules
                if not (r.match == rule.match and r.pattern.lower() == rule.pattern.lower())
            ]
            self.rules.append(rule)
            self.save()
        return rule

    def add_from_alert(
        self,
        label: Label,
        *,
        comm: str | None = None,
        path: str | None = None,
        name: str | None = None,
        cmdline: str | None = None,
        rule_id: str = "",
        note: str = "",
        widen: str | bool | None = None,
        source: str = "tg",
    ) -> list[ProcessLabelRule]:
        """Create exact rule; optionally widen to similar processes."""
        key = process_key(comm=comm, path=path, name=name)
        created: list[ProcessLabelRule] = []
        if not key and not (path or cmdline):
            return created
        if key:
            created.append(
                self.add_rule(
                    ProcessLabelRule(
                        id=uuid.uuid4().hex[:12],
                        label=label,
                        match="exact",
                        pattern=key,
                        source=source,
                        note=note or label,
                        path=(path or "")[:512],
                        rule_id=rule_id,
                    )
                )
            )
        widen_mode = widen
        if widen is True:
            widen_mode = "comm_prefix"
        if widen_mode in ("comm_prefix", "path_glob", "both"):
            c = (comm or name or key or "").strip()
            if c and widen_mode in ("comm_prefix", "both"):
                # strip trailing digits for firefox123 → firefox (light widen)
                base = re.sub(r"\d+$", "", c.lower()).rstrip("-_") or c.lower()
                created.append(
                    self.add_rule(
                        ProcessLabelRule(
                            id=uuid.uuid4().hex[:12],
                            label=label,
                            match="comm_prefix",
                            pattern=base,
                            source=source,
                            note=f"widen:{note or label}",
                            path=(path or "")[:512],
                            rule_id=rule_id,
                        )
                    )
                )
            if path and widen_mode in ("path_glob", "both"):
                parent = str(Path(path).parent)
                if parent and parent not in (".", "/"):
                    created.append(
                        self.add_rule(
                            ProcessLabelRule(
                                id=uuid.uuid4().hex[:12],
                                label=label,
                                match="path_glob",
                                pattern=f"{parent}/*",
                                source=source,
                                note=f"widen-path:{note or label}",
                                path=path[:512],
                                rule_id=rule_id,
                            )
                        )
                    )
        return created

    def delete(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self.rules)
            self.rules = [r for r in self.rules if r.id != rule_id and r.pattern != rule_id]
            if len(self.rules) == before:
                return False
            self.save()
            return True

    def match(
        self,
        *,
        comm: str | None = None,
        path: str | None = None,
        name: str | None = None,
        cmdline: str | None = None,
        rule_id: str | None = None,
    ) -> ProcessLabelRule | None:
        c = comm or name or ""
        p = path or ""
        cmd = cmdline or ""
        rid = (rule_id or "").strip()
        now = time.time()
        best: ProcessLabelRule | None = None
        best_pri = -1
        with self._lock:
            active = [r for r in self.rules if not r.expired(now)]
            for r in active:
                if not _rule_matches(r, comm=c, path=p, cmdline=cmd, alert_rule_id=rid):
                    continue
                pri = _LABEL_PRIORITY.get(r.label, 0)
                if pri > best_pri:
                    best = r
                    best_pri = pri
        return best

    def mute_rule(
        self,
        rule_id: str,
        *,
        label: Label = "ignore",
        note: str = "",
        source: str = "tg",
        expires_at: float | None = None,
    ) -> ProcessLabelRule | None:
        """Mute/baseline an entire alert rule_id (e.g. kirk module_hide FP)."""
        rid = (rule_id or "").strip()
        if not rid:
            return None
        return self.add_rule(
            ProcessLabelRule(
                id=uuid.uuid4().hex[:12],
                label=label,
                match="rule_id",
                pattern=rid,
                source=source,
                note=note or f"mute:{rid}",
                rule_id=rid,
                expires_at=expires_at,
            )
        )

    def is_rule_muted(self, rule_id: str | None) -> bool:
        rid = (rule_id or "").strip()
        if not rid:
            return False
        e = self.match(rule_id=rid)
        return e is not None and e.label == "ignore"

    # --- OperatorFeedback-compatible API ---

    def remember(
        self,
        kind: Label,
        *,
        comm: str | None = None,
        path: str | None = None,
        name: str | None = None,
        rule_id: str = "",
        note: str = "",
        widen: str | bool | None = None,
    ) -> ProcessLabelRule | None:
        created = self.add_from_alert(
            kind,
            comm=comm,
            path=path,
            name=name,
            rule_id=rule_id,
            note=note,
            widen=widen,
        )
        if created:
            return created[0]
        # No process identity — still mute by alert rule_id when present
        if kind == "ignore" and rule_id:
            return self.mute_rule(rule_id, note=note or "tg-ignore")
        return None

    def lookup(self, **kwargs: Any) -> ProcessLabelRule | None:
        return self.match(**kwargs)

    def is_ignored(self, **kwargs: Any) -> bool:
        e = self.match(**kwargs)
        return e is not None and e.label == "ignore"

    def is_baseline(self, **kwargs: Any) -> bool:
        e = self.match(**kwargs)
        return e is not None and e.label == "baseline"

    def is_anomaly(self, **kwargs: Any) -> bool:
        e = self.match(**kwargs)
        return e is not None and e.label == "anomaly"

    def adjust_score(self, score: float, **kwargs: Any) -> float:
        e = self.match(**kwargs)
        if e is None:
            return float(score)
        s = float(score)
        if e.label == "ignore":
            return 0.0
        if e.label == "baseline":
            return max(0.0, s * 0.35)
        if e.label == "anomaly":
            return min(1.0, max(s, 0.85) + 0.1)
        return s

    def should_suppress_alert(self, **kwargs: Any) -> bool:
        e = self.match(**kwargs)
        return e is not None and e.label == "ignore"

    def list_rules(self) -> list[ProcessLabelRule]:
        with self._lock:
            return list(self.rules)

    # aliases used by telegram (kind attribute)
    @property
    def entries(self) -> dict[str, ProcessLabelRule]:
        return {r.pattern: r for r in self.rules if r.match == "exact"}


# Back-compat alias
OperatorFeedback = ProcessLabelStore
FeedbackEntry = ProcessLabelRule
