from unittest.mock import patch

from sysspectogram.admin_ip import cidr_for_ip, merge_never_ban, seed_never_ban


def test_cidr_for_ip():
    assert cidr_for_ip("203.0.113.10") == "203.0.113.10/32"
    assert cidr_for_ip("203.0.113.0/24") == "203.0.113.0/24"


def test_merge_never_ban_idempotent():
    assert merge_never_ban([], "203.0.113.10") == ["203.0.113.10/32"]
    assert merge_never_ban(["203.0.113.10/32"], "203.0.113.10") == ["203.0.113.10/32"]
    assert merge_never_ban(["203.0.113.0/24"], "203.0.113.10") == ["203.0.113.0/24"]


def test_seed_detect_failed(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    with patch("sysspectogram.admin_ip.detect_public_ip", return_value=None):
        out = seed_never_ban(write=True)
    assert out["ok"] is False
    assert out["reason"] == "detect_failed"


def test_seed_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    with patch("sysspectogram.admin_ip.detect_public_ip", return_value="198.51.100.9"):
        out = seed_never_ban(write=True)
    assert out["ok"] is True
    assert out["written"] is True
    assert "198.51.100.9/32" in out["never_ban_cidrs"]
