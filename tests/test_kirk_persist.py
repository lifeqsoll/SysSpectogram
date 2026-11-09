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
    nft.ssh_port = 22
    nft.https_egress_cidrs = None
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


def test_kirk_https_rules_are_addressed(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    nft = _bare_nft(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(list(cmd))
        return 0, ""

    monkeypatch.setattr(nft, "_run", fake_run)
    nft.https_egress_cidrs = ["203.0.113.0/24"]
    monkeypatch.setattr(
        "sysspectogram.response.actions._dns_egress_targets",
        lambda: [("ip", "192.0.2.53")],
    )
    out = nft.kirk_isolate(allow_cidrs=["203.0.113.10/32"], ttl_sec=120)
    assert out.startswith("kirk_isolate active")
    bare_443 = [
        c
        for c in calls
        if "443" in c and "daddr" not in c
    ]
    bare_53 = [c for c in calls if "53" in c and "daddr" not in c]
    assert bare_443 == []
    assert bare_53 == []
    assert any("daddr" in c and "443" in c and "203.0.113.0/24" in c for c in calls)
    assert any("daddr" in c and "53" in c and "192.0.2.53" in c for c in calls)


def test_stub_resolv_uses_resolvectl(monkeypatch):
    from pathlib import Path

    from sysspectogram.response.actions import _dns_egress_targets

    real_read = Path.read_text

    def fake_read(self, *args, **kwargs):
        if str(self) == "/etc/resolv.conf":
            return "nameserver 127.0.0.53\n"
        return real_read(self, *args, **kwargs)

    def fake_run(argv, **kwargs):
        class P:
            stdout = "Link 2 (eth0): 192.0.2.53\n"
            stderr = ""
            returncode = 0

        if argv and argv[0] == "resolvectl":
            return P()
        raise AssertionError(argv)

    monkeypatch.setattr(Path, "read_text", fake_read)
    monkeypatch.setattr("sysspectogram.response.actions.subprocess.run", fake_run)
    assert ("ip", "192.0.2.53", (53,)) in _dns_egress_targets()


def test_resolvectl_keeps_ipv6_and_dot(monkeypatch):
    from sysspectogram.response.actions import _parse_resolvectl_dns

    text = (
        "Global: 203.0.113.9#dns.example\n"
        "Link 2 (eth0): 192.0.2.53 2001:db8::53\n"
    )
    got = _parse_resolvectl_dns(text)
    assert ("ip", "203.0.113.9", (53, 853)) in got
    assert ("ip", "192.0.2.53", (53,)) in got
    assert ("ip6", "2001:db8::53", (53,)) in got
    bracket = _parse_resolvectl_dns("Global: [2001:db8::54]:853 192.0.2.54%eth0\n")
    assert ("ip6", "2001:db8::54", (53, 853)) in bracket
    assert ("ip", "192.0.2.54", (53,)) in bracket


def test_constructor_does_not_release_kirk(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_HOME", str(tmp_path))
    (tmp_path / "state").mkdir()
    released: list[str] = []

    def fake_run(cmd):
        if "list" in cmd and "ss_kirk" in cmd:
            return 0, "table inet ss_kirk"
        if "delete" in cmd and "ss_kirk" in cmd:
            released.append("yes")
            return 0, ""
        return 0, ""

    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which", lambda _n: "/usr/sbin/nft"
    )
    from sysspectogram.response.actions import NftBackend

    monkeypatch.setattr(NftBackend, "_run", lambda self, cmd: fake_run(cmd))
    nft = NftBackend()
    assert released == []
    nft.reconcile_kirk_from_disk()
    assert released == ["yes"]


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
