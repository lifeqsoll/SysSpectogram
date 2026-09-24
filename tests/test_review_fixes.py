from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

from sysspectogram.integrations.webhook import post_webhook
from sysspectogram.ml.calibration import suggested_threshold_hint, CalibrationState
from sysspectogram.osint.recon import run_full_recon
from sysspectogram.perimeter.connections import _parse_ipv6
from sysspectogram.perimeter.watcher import PerimeterWatcher, WatcherState
from sysspectogram.preprocess.dataset_builder import build_dataset
from sysspectogram.response.actions import NftBackend


def test_parse_ipv6_word_endian():
    # Construct little-endian 32-bit words for ::1
    packed = b"\x00" * 15 + b"\x01"
    words = []
    for i in range(0, 16, 4):
        words.append(struct.unpack(">I", packed[i : i + 4])[0])
    # /proc stores each 32-bit word little-endian
    hex_parts = []
    for w in words:
        hex_parts.append(struct.pack("<I", w).hex())
    ip_hex = "".join(hex_parts)
    assert _parse_ipv6(ip_hex) in {"::1", "0:0:0:0:0:0:0:1"}


def test_nft_unban_uses_handle():
    backend = NftBackend()
    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:2] == ["nft", "-a"] or (len(cmd) > 1 and cmd[1] == "-a"):
            return 0, 'ip saddr 203.0.113.9 drop comment "sysspectogram:203.0.113.9:0" # handle 42\n'
        if "delete" in cmd:
            return 0, ""
        if cmd[:2] == ["nft", "add"]:
            return 0, ""
        return 0, ""

    with patch.object(backend, "_run", side_effect=fake_run), patch(
        "sysspectogram.response.actions.shutil.which", return_value="/usr/sbin/nft"
    ):
        msg = backend.ban_ip("203.0.113.9", ttl_sec=60)
        assert "handle=42" in msg or "banned" in msg
        umsg = backend.unban_ip("203.0.113.9")
        assert any("delete" in c and "42" in c for c in calls)
        assert "42" in umsg or "unbanned" in umsg


def test_lockdown_flag_applies_nft(tmp_path: Path):
    backend = NftBackend()
    applied = {"n": 0}

    def fake_apply(dry_run=False):
        applied["n"] += 1
        return "lockdown ok"

    backend.apply_lockdown = fake_apply  # type: ignore
    w = PerimeterWatcher(state_path=tmp_path / "st.json", nft=backend, auto_recon=False)
    assert "lockdown" in w.apply_lockdown().lower() or applied["n"] == 1
    assert w.state.lockdown is True


def test_recon_nmap_lab_gated():
    report = run_full_recon(
        "203.0.113.50",
        include_nmap=True,
        lab_targets=["127.0.0.1"],
        require_lab_for_nmap=True,
        include_ct=False,
    )
    assert report.nmap.get("skipped") is True
    assert "lab" in str(report.nmap.get("reason", "")).lower() or "blocked" in str(
        report.nmap.get("reason", "")
    ).lower()


def test_temporal_val_split(tmp_path: Path):
    cols = ["timestamp", "cpu_percent", "mem_percent", "net_packets_sent_per_s"]
    rows_n = []
    rows_a = []
    for i in range(120):
        rows_n.append(
            {
                "timestamp": i,
                "cpu_percent": 5.0,
                "mem_percent": 20.0,
                "net_packets_sent_per_s": 10.0,
            }
        )
        rows_a.append(
            {
                "timestamp": i,
                "cpu_percent": 90.0,
                "mem_percent": 70.0,
                "net_packets_sent_per_s": 200.0,
            }
        )
    ncsv = tmp_path / "n.csv"
    acsv = tmp_path / "a.csv"
    pd.DataFrame(rows_n).to_csv(ncsv, index=False)
    pd.DataFrame(rows_a).to_csv(acsv, index=False)
    out = tmp_path / "ds"
    meta = build_dataset(
        [ncsv],
        [acsv],
        out,
        window_size=10,
        stride=10,
        val_ratio=0.2,
        max_normal_cpu_mean=50,
        min_anomaly_cpu_mean=40,
        max_normal_mem_mean=90,
        min_anomaly_mem_mean=10,
        max_normal_pkt_mean=500,
        min_anomaly_pkt_mean=1,
        balance=True,
    )
    assert meta["counts"]["val"]["normal"] > 0
    assert meta["counts"]["train"]["normal"] > 0


def test_webhook_hmac_header(monkeypatch):
    captured = {}

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=8.0):
        captured["headers"] = dict(req.headers)
        captured["data"] = req.data
        return FakeResp()

    monkeypatch.setattr(
        "sysspectogram.integrations.webhook.urllib.request.urlopen", fake_urlopen
    )
    ok, _ = post_webhook("http://example.test/hook", {"a": 1}, secret="sekrit")
    assert ok
    headers_l = {k.lower(): v for k, v in captured["headers"].items()}
    assert "x-sysspectogram-signature" in headers_l
    body = captured["data"]
    expect = hmac.new(b"sekrit", body, hashlib.sha256).hexdigest()
    assert expect in headers_l["x-sysspectogram-signature"]


def test_suggested_threshold_hint():
    st = CalibrationState(score_mean=0.1, score_std=0.05, n=50)
    hint = suggested_threshold_hint(st, [0.8, 0.85, 0.9], current_threshold=0.4)
    assert hint is not None
    assert hint > 0.4
