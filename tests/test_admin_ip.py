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


def test_seed_refuses_corrupt_user_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir(parents=True)
    bad = state / "user-settings.json"
    bad.write_text("{not-json", encoding="utf-8")
    with patch("sysspectogram.admin_ip.detect_public_ip", return_value="198.51.100.9"):
        out = seed_never_ban(write=True)
    assert out["ok"] is False
    assert out["reason"] == "user_settings_corrupt"
    assert bad.read_text(encoding="utf-8") == "{not-json"


def test_seed_force_backs_up_corrupt(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    state = tmp_path / "state"
    state.mkdir(parents=True)
    bad = state / "user-settings.json"
    bad.write_text("{not-json", encoding="utf-8")
    with patch("sysspectogram.admin_ip.detect_public_ip", return_value="198.51.100.9"):
        out = seed_never_ban(write=True, force=True)
    assert out["ok"] is True
    assert out["written"] is True
    assert (state / "user-settings.json.bak").read_text(encoding="utf-8") == "{not-json"
    assert "198.51.100.9/32" in bad.read_text(encoding="utf-8")


def test_seed_explicit_ip_skips_detect(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    with patch("sysspectogram.admin_ip.detect_public_ip") as det:
        out = seed_never_ban(write=True, ip="203.0.113.55")
    det.assert_not_called()
    assert out["ok"] is True
    assert "203.0.113.55/32" in out["never_ban_cidrs"]
