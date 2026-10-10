"""Fuse host ML score with agent IF score into one risk value and decide alerts.

Formula (unchanged): fused = host_weight * host + agent_weight * agent (normalized).
Decision gate (changed in v1.0, see docs/adr/0001-fusion-gating.md):
    anomaly = host >= host_threshold  OR  fused >= risk_threshold
so a host-only anomaly can alert even when the agent is quiet.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

CRITICAL_KIRK_RULES = frozenset(
    {
        "agent_kirk_module_hide",
        "agent_kirk_pid_hide",
        "agent_kirk_symbol_drift",
        "agent_kirk_ima_mismatch",
        "agent_kirk_agent_down",
    }
)

DEFAULT_AGENT_HALF_LIFE_SEC = 60.0


def decay_agent_score(
    score: float,
    age_sec: float | None,
    half_life_sec: float = DEFAULT_AGENT_HALF_LIFE_SEC,
) -> float:
    """Exponentially decay an agent score by its age.

    An unknown age returns the score without decay (no timestamp to decay from).
    """
    if age_sec is None or half_life_sec <= 0:
        return float(score)
    age = max(0.0, float(age_sec))
    return float(score) * math.exp(-math.log(2.0) * age / half_life_sec)


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


@dataclass(frozen=True)
class RiskDecision:
    risk: float
    is_anomaly: bool
    reason: str  # "host", "fused" or "none"


def decide_risk(
    host_score: float,
    agent_score: float | None,
    agent_age_sec: float | None,
    *,
    host_threshold: float,
    risk_threshold: float,
    host_weight: float = 0.6,
    agent_weight: float = 0.4,
    agent_half_life_sec: float = DEFAULT_AGENT_HALF_LIFE_SEC,
) -> RiskDecision:
    """Return the fused risk and whether the host window is anomalous."""
    decayed = None
    if agent_score is not None:
        decayed = decay_agent_score(agent_score, agent_age_sec, agent_half_life_sec)
    risk = fuse_host_agent(
        host_score,
        decayed if decayed is not None else 0.0,
        host_weight=host_weight,
        agent_weight=agent_weight,
    )
    if host_score >= host_threshold:
        return RiskDecision(risk=risk, is_anomaly=True, reason="host")
    if risk >= risk_threshold:
        return RiskDecision(risk=risk, is_anomaly=True, reason="fused")
    return RiskDecision(risk=risk, is_anomaly=False, reason="none")


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
