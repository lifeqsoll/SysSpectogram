from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sysspectogram.alerts.fanout import AlertFanout, _is_private_host, _sink_host_blocked


def test_file_sink(tmp_path):
    path = tmp_path / "a.jsonl"
    fan = AlertFanout([{"type": "file", "path": str(path)}])
    fan.emit({"type": "host_anomaly", "score": 0.9})
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["type"] == "host_anomaly"
    assert "ts" in row


def test_https_sink_posts():
    fan = AlertFanout(
        [{"type": "https", "url": "https://example.test/ingest", "timeout": 1}],
        allow_private_sinks=False,
    )
    public = [
        (0, 0, 0, "", ("93.184.216.34", 0)),
    ]
    with patch("sysspectogram.alerts.fanout.socket.getaddrinfo", return_value=public):
        with patch("urllib.request.urlopen") as urlopen:
            resp = MagicMock()
            resp.read.return_value = b"ok"
            resp.__enter__.return_value = resp
            resp.__exit__.return_value = False
            urlopen.return_value = resp
            fan.emit({"type": "probe"})
            assert urlopen.called


def test_https_ssrf_blocked():
    fan = AlertFanout(
        [{"type": "https", "url": "https://169.254.169.254/latest/meta-data/"}],
        allow_private_sinks=False,
    )
    # fail-open: emit should not raise
    fan.emit({"type": "probe"})


def test_https_ssrf_hostname_dns_blocked():
    """Hostname resolving to link-local must be blocked (nip.io-style bypass)."""
    fan = AlertFanout(
        [{"type": "https", "url": "https://evil.nip.io/ingest", "timeout": 1}],
        allow_private_sinks=False,
    )
    link_local = [
        (0, 0, 0, "", ("169.254.169.254", 0)),
    ]
    with patch("sysspectogram.alerts.fanout.socket.getaddrinfo", return_value=link_local):
        with patch("urllib.request.urlopen") as urlopen:
            fan.emit({"type": "probe"})
            assert not urlopen.called


def test_https_inline_token_strict():
    fan = AlertFanout(
        [{"type": "https", "url": "https://example.test/x", "token": "secret"}],
        strict_secrets=True,
    )
    with patch(
        "sysspectogram.alerts.fanout.socket.getaddrinfo",
        return_value=[(0, 0, 0, "", ("1.2.3.4", 0))],
    ):
        fan.emit({"type": "probe"})  # fail-open logs warning


def test_syslog_udp_send():
    fan = AlertFanout(
        [{"type": "syslog", "host": "127.0.0.1", "port": 6514, "transport": "udp"}]
    )
    with patch("socket.socket") as sock_cls:
        sock = MagicMock()
        sock_cls.return_value = sock
        fan.emit({"type": "probe"})
        assert sock.sendto.called


def test_from_config_default_file():
    fan = AlertFanout.from_config({"perimeter": {"jsonl_out": "reports/x.jsonl"}})
    assert fan.sinks[0]["type"] == "file"


def test_private_host_helper():
    assert _is_private_host("127.0.0.1")
    assert _is_private_host("10.0.0.1")
    assert _is_private_host("169.254.1.1")
    assert not _is_private_host("8.8.8.8")
    assert not _is_private_host("evil.nip.io")  # string-only; DNS checked separately


def test_sink_host_blocked_resolves():
    with patch(
        "sysspectogram.alerts.fanout.socket.getaddrinfo",
        return_value=[(0, 0, 0, "", ("10.0.0.5", 0))],
    ):
        assert _sink_host_blocked("internal.example")
    with patch(
        "sysspectogram.alerts.fanout.socket.getaddrinfo",
        return_value=[(0, 0, 0, "", ("8.8.8.8", 0))],
    ):
        assert not _sink_host_blocked("dns.google")
