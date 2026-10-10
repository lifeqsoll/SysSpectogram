from __future__ import annotations

import math

from sysspectogram.risk import apply_kirk_override, decay_agent_score, decide_risk, fuse_host_agent


def test_decay_halves_at_half_life():
    assert math.isclose(decay_agent_score(0.8, 60.0, 60.0), 0.4, rel_tol=1e-9)


def test_decay_unknown_age_keeps_score():
    assert decay_agent_score(0.8, None, 60.0) == 0.8


def test_fuse_without_agent_is_host_score():
    assert fuse_host_agent(0.5, None) == 0.5


def test_host_alone_above_threshold_alerts():
    d = decide_risk(0.995, None, None, host_threshold=0.99, risk_threshold=0.7)
    assert d.is_anomaly and d.reason == "host"


def test_quiet_everything_is_no_anomaly():
    d = decide_risk(0.2, 0.0, 0.0, host_threshold=0.99, risk_threshold=0.7)
    assert not d.is_anomaly and d.reason == "none"


def test_fresh_agent_pushes_fused_over_threshold():
    # host 0.75 is below its own threshold; fresh agent 0.9 lifts fused to 0.81
    d = decide_risk(0.75, 0.9, 0.0, host_threshold=0.99, risk_threshold=0.7)
    assert math.isclose(d.risk, 0.6 * 0.75 + 0.4 * 0.9, rel_tol=1e-9)
    assert d.is_anomaly and d.reason == "fused"


def test_stale_agent_score_decays_and_stops_alerting():
    # ten half-lives later the agent contributes almost nothing
    d = decide_risk(0.75, 0.9, 600.0, host_threshold=0.99, risk_threshold=0.7, agent_half_life_sec=60.0)
    assert not d.is_anomaly


def test_kirk_override_only_for_allowlisted_rules():
    assert apply_kirk_override(0.1, rule_id="agent_kirk_pid_hide", severity="critical") > 0.7
    assert apply_kirk_override(0.1, rule_id="random_rule", severity="critical") == 0.1
