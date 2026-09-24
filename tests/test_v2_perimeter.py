from __future__ import annotations

from pathlib import Path

from sysspectogram.explain.templates import explain_host_anomaly, explain_perimeter
from sysspectogram.osint.recon import nmap_fast, run_full_recon
from sysspectogram.perimeter.auth import parse_auth_lines
from sysspectogram.perimeter.rules import Alert, Denylist, RuleEngine
from sysspectogram.response.tokens import TokenStore


def test_parse_auth_failed():
    lines = [
        "Failed password for root from 203.0.113.9 port 22 ssh2",
        "Invalid user admin from 198.51.100.1",
        "Accepted publickey for alice from 192.0.2.10 port 22 ssh2",
        "noise",
    ]
    ev = parse_auth_lines(lines)
    assert [e.kind for e in ev] == ["failed", "invalid", "accepted"]
    assert ev[0].ip == "203.0.113.9"


def test_bruteforce_rule():
    eng = RuleEngine(fail_threshold=5, fail_window_sec=60)
    last = None
    for _ in range(5):
        last = eng.on_auth_fail("203.0.113.20", "root")
    assert last is not None
    assert last.rule_id == "bruteforce_ssh"


def test_allowlist_blocks_brute():
    eng = RuleEngine(fail_threshold=3, allowlist={"203.0.113.1"})
    for _ in range(5):
        assert eng.on_auth_fail("203.0.113.1") is None


def test_port_scan_rule():
    eng = RuleEngine(scan_unique_ips=4, scan_window_sec=60)
    last = None
    for i in range(4):
        last = eng.on_inbound(f"203.0.113.{i}", 22)
    assert last is not None
    assert last.rule_id == "port_scan_suspected"


def test_denylist_egress(tmp_path: Path):
    dl = tmp_path / "dl.txt"
    dl.write_text("203.0.113.66\n", encoding="utf-8")
    eng = RuleEngine(denylist=Denylist([dl]))
    eng.seed_egress([])
    a = eng.on_egress("203.0.113.66", 4444, "beacon")
    assert a is not None
    assert a.rule_id == "egress_denylist_hit"


def test_unusual_egress_port_alerts():
    eng = RuleEngine(alert_new_egress=False)
    eng.seed_egress([])
    a = eng.on_egress("203.0.113.70", 4444, "x")
    assert a is not None
    assert a.rule_id == "suspicious_egress"
    # common https should not alert when alert_new_egress is false
    assert eng.on_egress("203.0.113.71", 443, "browser") is None


def test_suspicious_dns_rule():
    eng = RuleEngine()
    a = eng.on_suspicious_dns("evil.malware.test")
    assert a is not None
    assert a.rule_id == "suspicious_dns"


def test_calibration_and_attribution():
    from sysspectogram.ml.calibration import CalibrationState, feature_attribution
    import numpy as np

    st = CalibrationState()
    st.update([0.1, 0.2, 0.15])
    assert st.n == 3
    w = np.random.rand(60, 4).astype(np.float32)
    feats = feature_attribution(w, ["a", "b", "c", "d"], top_k=2)
    assert len(feats) == 2


def test_explain_templates():
    a = Alert("bruteforce_ssh", "critical", "x", ip="1.2.3.4", extras={"fails": 9})
    assert "SSH" in explain_perimeter(a)
    assert "CPU" in explain_host_anomaly(cpu=90.0, top_procs=[{"name": "x", "pid": 1, "cpu_percent": 80}])


def test_token_issue_consume():
    store = TokenStore(secret="testsecret")
    tok = store.issue("ban", {"ip": "203.0.113.1", "ttl": 3600}, ttl_sec=60)
    assert store.peek(tok) is not None
    got = store.consume(tok)
    assert got is not None
    assert got[0] == "ban"
    assert got[1]["ip"] == "203.0.113.1"
    assert store.consume(tok) is None


def test_nmap_soft_fail_without_binary(monkeypatch):
    monkeypatch.setattr("sysspectogram.osint.recon._which", lambda _: None)
    monkeypatch.setattr("shutil.which", lambda *a, **k: None)
    res = nmap_fast("203.0.113.1")
    assert res.get("skipped") is True
    assert res.get("open_ports") == []


def test_recon_soft_fail_no_network(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("offline")

    monkeypatch.setattr("sysspectogram.osint.recon.enrich_ip_http", boom)
    monkeypatch.setattr("sysspectogram.osint.recon.nmap_fast", lambda ip, timeout_sec=60: {"skipped": True, "reason": "nmap not installed", "open_ports": []})
    report = run_full_recon("203.0.113.1", include_nmap=True, include_ct=False)
    assert report.ip == "203.0.113.1"
    assert any("enrich" in e for e in report.errors)
