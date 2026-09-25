"""Kirk trust + risk override unit tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from sysspectogram.kirk_trust import KirkTrustReport, ima_watch_new_lines, probe_kirk_trust
from sysspectogram.risk import apply_kirk_override, fuse_host_agent


def test_fuse_basic():
    assert abs(fuse_host_agent(1.0, 0.0, host_weight=0.6, agent_weight=0.4) - 0.6) < 1e-9


def test_kirk_override_critical_rule():
    assert apply_kirk_override(0.1, rule_id="agent_kirk_module_hide", severity="critical", risk_threshold=0.7) >= 0.75
    assert apply_kirk_override(0.1, rule_id="agent_ebpf_execve", severity="critical") == 0.1
    # forged kirk rule name not in allowlist
    assert apply_kirk_override(0.2, rule_id="agent_kirk_foo", severity="critical") == 0.2


def test_probe_returns_report():
    r = probe_kirk_trust()
    assert isinstance(r, KirkTrustReport)
    assert r.trust in ("best-effort", "measured")


def test_ima_watch_offset(tmp_path: Path):
    # no IMA path → empty
    state = tmp_path / "off.txt"
    with patch("sysspectogram.kirk_trust._ima_ascii_path", return_value=tmp_path / "missing"):
        assert ima_watch_new_lines(state) == []
