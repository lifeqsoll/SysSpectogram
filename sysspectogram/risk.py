"""Fuse host ML score with agent IF score into one risk value."""

from __future__ import annotations

CRITICAL_KIRK_RULES = frozenset(
    {
        "agent_kirk_module_hide",
        "agent_kirk_pid_hide",
        "agent_kirk_symbol_drift",
        "agent_kirk_ima_mismatch",
        "agent_kirk_agent_down",
    }
)


def fuse_host_agent(
    host_score: float,
    agent_score: float | None,
    *,
    host_weight: float = 0.6,
    agent_weight: float = 0.4,
) -> float:
    if agent_score is None:
        return float(host_score)
    total = host_weight + agent_weight
    if total <= 0:
        return float(host_score)
    wh = host_weight / total
    wa = agent_weight / total
    return float(wh * host_score + wa * agent_score)


def apply_kirk_override(
    risk: float,
    *,
    rule_id: str | None = None,
    severity: str | None = None,
    risk_threshold: float = 0.7,
    eps: float = 0.05,
) -> float:
    """Force risk above threshold for CRITICAL kirk signals (allowlisted rules only)."""
    rid = (rule_id or "").strip()
    sev = (severity or "").strip().lower()
    # Do not trust arbitrary severity=critical alone (socket forge).
    hit = rid in CRITICAL_KIRK_RULES and sev in ("critical", "high")
    if not hit:
        return float(risk)
    # symbol_drift may be high (presence missing) — still elevate, isolate stays separate
    return max(float(risk), float(risk_threshold) + float(eps))
