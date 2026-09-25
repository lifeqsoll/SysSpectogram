"""Fuse host ML score with agent IF score into one risk value."""

from __future__ import annotations


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
