"""kirk_isolate deadline on disk + rollback on allow failure + shield sweeper."""

from __future__ import annotations

import json
import time
from pathlib import Path


def _bare_nft(monkeypatch):
    from sysspectogram.response.actions import NftBackend

    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which", lambda _n: "/usr/sbin/nft"
    )
    nft = NftBackend.__new__(NftBackend)
    nft.table = "inet"
    nft.chain = "sysspectogram"
    nft.bans = {}
    nft.never_ban_cidrs = []
    nft.max_ban_ttl_sec = 604800.0
    nft._kirk_expires = None
    return nft


def test_kirk_isolate_writes_deadline(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    nft = _bare_nft(monkeypatch)

    def fake_run(cmd):
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    out = nft.kirk_isolate(allow_cidrs=["203.0.113.10/32"], ttl_sec=120)
    assert out.startswith("kirk_isolate active")
    path = tmp_path / "state" / "kirk_isolate.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["expires_at"] > time.time()
    assert data["allow_cidrs"] == ["203.0.113.10/32"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_kirk_expire_on_new_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    path = tmp_path / "state" / "kirk_isolate.json"
    path.write_text(
        json.dumps({"expires_at": time.time() - 10, "allow_cidrs": ["203.0.113.10/32"]}),
        encoding="utf-8",
    )

    nft = _bare_nft(monkeypatch)
    released: list[str] = []

    def fake_run(cmd):
        if cmd[:3] == ["nft", "list", "table"]:
            return 0, "table inet ss_kirk"
        if cmd[:3] == ["nft", "delete", "table"]:
            released.append("yes")
            return 0, ""
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    nft._load_kirk_deadline()
    assert released == ["yes"]
    assert not path.exists()


def test_kirk_rollback_on_allow_fail(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    nft = _bare_nft(monkeypatch)
    deleted = []

    def fake_run(cmd):
        joined = " ".join(cmd)
        if "delete" in cmd and "ss_kirk" in joined:
            deleted.append(True)
            return 0, ""
        if "dport" in cmd and "22" in cmd and "saddr" in joined:
            return 1, "boom allow"
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    out = nft.kirk_isolate(allow_cidrs=["203.0.113.10/32"], ttl_sec=120)
    assert "failed" in out
    assert deleted
    assert not (tmp_path / "state" / "kirk_isolate.json").exists()


def test_expire_shield_ports_removes_expired(monkeypatch, tmp_path):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    nft = _bare_nft(monkeypatch)
    past = int(time.time()) - 10
    listing = (
        f'ip saddr 203.0.113.10 tcp dport 8080 accept comment "sysspectogram:portallow:8080:203.0.113.10/32" # handle 10\n'
        f'tcp dport 8080 drop comment "sysspectogram:port:8080:{past}" # handle 11\n'
    )
    deleted: list[str] = []

    def fake_run(cmd):
        if cmd[:2] == ["nft", "-a"]:
            return 0, listing
        if "delete" in cmd and "handle" in cmd:
            deleted.append(cmd[-1])
            return 0, ""
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    msg = nft.expire_shield_ports()
    assert msg and "removed=" in msg
    assert "11" in deleted
    assert "10" in deleted
