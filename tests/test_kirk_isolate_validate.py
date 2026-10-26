"""kirk_isolate must refuse bad CIDRs before creating a policy-drop table."""

from __future__ import annotations

from unittest.mock import MagicMock

from sysspectogram.response.actions import NftBackend


def test_kirk_isolate_refuses_bad_cidr_before_nft(monkeypatch):
    nft = NftBackend(never_ban_cidrs=[])
    calls: list[list[str]] = []

    def fake_run(argv):  # noqa: ANN001
        calls.append(list(argv))
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which",
        lambda name: "/usr/sbin/nft" if name == "nft" else None,
    )

    out = nft.kirk_isolate(allow_cidrs=["203.0.113.10/32", "abc"], dry_run=False)
    assert out.startswith("kirk_isolate refused")
    assert "abc" in out or "invalid" in out.lower()
    # Must not have touched nft at all (no add table / drop policy).
    assert calls == []


def test_kirk_isolate_refuses_overwide_prefix_before_nft(monkeypatch):
    nft = NftBackend(never_ban_cidrs=[])
    calls: list[list[str]] = []
    monkeypatch.setattr(nft, "_run", lambda argv: calls.append(list(argv)) or (0, ""))
    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which",
        lambda name: "/usr/sbin/nft" if name == "nft" else None,
    )
    out = nft.kirk_isolate(allow_cidrs=["1.2.3.4/40"], dry_run=False)
    assert out.startswith("kirk_isolate refused")
    assert calls == []


def test_kirk_isolate_dry_run_after_validate():
    nft = NftBackend(never_ban_cidrs=[])
    out = nft.kirk_isolate(allow_cidrs=["203.0.113.10/32"], dry_run=True, ttl_sec=120)
    assert out.startswith("dry-run kirk_isolate")
    assert "203.0.113.10/32" in out


def test_home_settings_rejects_bad_allow_ssh(tmp_path, monkeypatch):
    import json
    from argparse import Namespace

    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir(parents=True)
    from sysspectogram.cli import _cmd_home_settings

    rc = _cmd_home_settings(
        Namespace(changes=json.dumps({"kirk.allow_ssh_cidrs": "abc, 1.2.3.4/40"}))
    )
    assert rc == 2
    assert not (tmp_path / "state" / "user-settings.json").exists()
