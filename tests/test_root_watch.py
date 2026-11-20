"""Root process watch tests."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from sysspectogram.root_watch import (
    DEFAULT_ALLOW_COMMS,
    DEFAULT_ALLOW_EXES,
    RootWatchState,
    list_root_procs,
    pid_under_trusted,
    poll_new_root,
    root_severity,
    save_root_baseline,
    soft_allow,
)

# Exact built-in exe paths. Comm is not part of this allowlist.
_EXACT_ALLOW_EXES = (
    "/usr/bin/journalctl",
    "/usr/bin/systemctl",
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/usr/sbin/ip",
    "/usr/bin/ip",
    "/usr/bin/ss",
    "/usr/bin/pacman",
    "/usr/bin/sudo",
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/sbin/cron",
    "/usr/bin/cron",
    "/usr/sbin/crond",
    "/usr/bin/crond",
    "/usr/bin/dbus-daemon",
    "/usr/sbin/NetworkManager",
    "/usr/bin/NetworkManager",
    "/usr/lib/systemd/systemd",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-udevd",
    "/usr/lib/systemd/systemd-logind",
    "/usr/lib/systemd/systemd-networkd",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/systemd/systemd-timesyncd",
    "/usr/sbin/logrotate",
    "/usr/bin/logrotate",
    "/usr/bin/mandb",
    "/usr/bin/updatedb",
    "/usr/sbin/fstrim",
    "/usr/bin/fstrim",
    "/usr/local/sbin/sysspectogram-agent",
    "/usr/sbin/sysspectogram-agent",
)


def test_list_root_does_not_crash():
    procs = list_root_procs(include_kernel=False)
    assert isinstance(procs, list)


def test_learn_then_empty():
    st = RootWatchState()
    # force end of learn
    st.baseline_until = 1.0
    st.baseline = {p.pid for p in list_root_procs(include_kernel=False)}
    news = poll_new_root(st, learn_sec=0.0)
    # everything currently root should already be baseline
    assert all(p.pid in st.baseline or p.pid in st.alerted for p in news) or news == []


def test_default_allow_includes_utilities():
    missing = [exe for exe in _EXACT_ALLOW_EXES if exe not in DEFAULT_ALLOW_EXES]
    assert missing == []


def test_soft_allow_utilities_need_system_exe():
    assert soft_allow("journalctl", "/usr/bin/journalctl", set(DEFAULT_ALLOW_COMMS))
    assert not soft_allow("journalctl", "/tmp/journalctl", set(DEFAULT_ALLOW_COMMS))
    assert soft_allow("sudo", "/usr/bin/sudo", set(DEFAULT_ALLOW_COMMS))


def test_sudo_child_not_auto_allowed_by_parent_name():
    # A random root binary is not soft-allowed even if parent was sudo.
    assert not soft_allow("evil", "/tmp/evil", set(DEFAULT_ALLOW_COMMS))


@pytest.mark.parametrize(
    ("comm", "exe"),
    [
        ("ipwn", "/tmp/ipwn"),
        ("ss-x", "/tmp/ss-x"),
        ("sshd", "/tmp/sshd"),
        ("systemd-x", "/tmp/systemd-x"),
        ("sudoer", "/dev/shm/sudoer"),
        ("nftx", "/tmp/nftx"),
        ("cron", "/root/.c/cron"),
        ("sshd-x", "/usr/sbin/sshd-x"),
    ],
)
def test_soft_allow_prefix_bypass_closed(comm: str, exe: str) -> None:
    assert soft_allow(comm, exe, set(DEFAULT_ALLOW_COMMS)) is False


def test_soft_allow_config_suffix_bypass_closed():
    assert soft_allow("zz", "/tmp/opt/mydaemon", {"/opt/mydaemon"}) is False
    assert soft_allow("zz", "/var/opt/mydaemon", {"/opt/mydaemon"}) is False
    assert soft_allow("zz", "/opt/mydaemon", {"/opt/mydaemon"}) is True
    assert soft_allow("zz", "/tmp/evil", {"/tmp/evil"}) is False


def test_soft_allow_config_comm_needs_system_exe():
    allow = {"mydaemon"}
    assert soft_allow("mydaemon", "/usr/bin/mydaemon", allow)
    assert not soft_allow("mydaemon", "/tmp/mydaemon", allow)
    assert not soft_allow("mydaemon-x", "/usr/bin/mydaemon", allow)


def test_journalctl_system_exe_allowed():
    assert soft_allow("journalctl", "/usr/bin/journalctl", set())
    assert not soft_allow("journalctl", "/tmp/journalctl", set())


def test_trusted_ppid_chain_skips(monkeypatch):
    st = RootWatchState()
    st.baseline_until = 1.0
    st.baseline = set()

    class Fake:
        def __init__(self, pid: int):
            self.pid = pid
            self.comm = "helper"
            self.exe = "/usr/bin/true"
            self.cmdline = "true"
            self.euid = 0
            self.ruid = 0
            self.severity = "critical"
            self.parent_comm = "python"

    monkeypatch.setattr(
        "sysspectogram.root_watch.list_root_pids_cheap", lambda: {424242}
    )
    monkeypatch.setattr(
        "sysspectogram.root_watch.describe_root_pid", lambda pid: Fake(pid)
    )
    monkeypatch.setattr(
        "sysspectogram.root_watch.pid_under_trusted", lambda pid, trusted: pid in trusted
    )
    news = poll_new_root(st, learn_sec=0.0, trusted_pids={424242})
    assert news == []


def test_pid_under_trusted_self():
    import os

    me = os.getpid()
    assert pid_under_trusted(me, {me})


def test_cron_child_is_medium_tmp_is_critical():
    assert root_severity("/usr/bin/backup.sh", "cron") == "medium"
    assert root_severity("/usr/bin/backup.sh", "systemd") == "medium"
    assert root_severity("/tmp/evil", "cron") == "critical"
    assert root_severity("/usr/bin/evil", "bash") == "critical"


def test_dedup_same_comm_exe(monkeypatch):
    st = RootWatchState()
    st.baseline_until = 1.0
    st.baseline = set()

    class Fake:
        def __init__(self, pid: int):
            self.pid = pid
            self.comm = "evilbin"
            self.exe = "/opt/evilbin"
            self.cmdline = "evilbin"
            self.euid = 0
            self.ruid = 0
            self.severity = "critical"
            self.parent_comm = "bash"

    calls = {"n": 0}

    def fake_list():
        calls["n"] += 1
        return {900001 + calls["n"]}

    def fake_describe(pid: int):
        return Fake(pid)

    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", fake_list)
    monkeypatch.setattr("sysspectogram.root_watch.describe_root_pid", fake_describe)
    monkeypatch.setattr("sysspectogram.root_watch.pid_under_trusted", lambda *a, **k: False)

    first = poll_new_root(st, learn_sec=0.0)
    assert len(first) == 1
    assert first[0].severity == "critical"
    second = poll_new_root(st, learn_sec=0.0)
    assert second == []  # dedup within window


def test_soft_allow_builtin_exe_after_canonicalize():
    udevd = "/usr/lib/systemd/systemd-udevd"
    if os.path.exists(udevd):
        # Comm is not part of the built-in match; the canonical exe is.
        assert soft_allow("not-systemd-udevd", udevd, set()) is True
    assert soft_allow("systemd-udevd", "/tmp/systemd-udevd", set()) is False


def test_interpret_exe_link_keeps_deleted_and_memfd():
    from sysspectogram.root_watch import _interpret_exe_link

    deleted = "/usr/bin/sudo (deleted)"
    assert _interpret_exe_link(deleted) == deleted
    assert soft_allow("sudo", deleted, set()) is False
    memfd = "memfd:evil (deleted)"
    assert _interpret_exe_link(memfd) == memfd


def _write_baseline(path: Path, saved_at: int, entries: list[dict]) -> None:
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    body = json.dumps(
        {"boot_id": boot, "saved_at": saved_at, "entries": entries}
    ).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, body)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def test_baseline_roundtrip_skips_learning(tmp_path, monkeypatch):
    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", lambda: set())
    path = tmp_path / "root_baseline.py.json"
    writer = RootWatchState()
    writer.baseline.add((1, 123, "/usr/sbin/sshd"))
    save_root_baseline(writer, path)

    reader = RootWatchState()
    poll_new_root(reader, learn_sec=300, baseline_path=path)
    assert reader.baseline_until <= time.time()
    assert (1, 123, "/usr/sbin/sshd") in reader.baseline

    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", lambda: {1})
    monkeypatch.setattr("sysspectogram.root_watch._read_starttime", lambda _pid: 124)

    class Fake:
        def __init__(self, pid: int):
            self.pid = pid
            self.comm = "evilbin"
            self.exe = "/opt/evilbin"
            self.cmdline = "evilbin"
            self.euid = 0
            self.ruid = 0
            self.severity = "critical"
            self.parent_comm = "bash"

    monkeypatch.setattr("sysspectogram.root_watch.describe_root_pid", lambda pid: Fake(pid))
    news = poll_new_root(reader, learn_sec=300, baseline_path=path)
    assert [p.pid for p in news] == [1]


def test_learn_snapshot_skips_learn_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", lambda: {7})
    monkeypatch.setattr("sysspectogram.root_watch._read_starttime", lambda _pid: 9)
    monkeypatch.setattr("sysspectogram.root_watch._read_exe", lambda _pid: "/usr/sbin/sshd")
    path = tmp_path / "root_baseline.py.json"
    learning = RootWatchState()
    assert poll_new_root(learning, learn_sec=300, baseline_path=path) == []
    assert path.is_file()
    assert learning.baseline_until > time.time()

    restarted = RootWatchState()
    poll_new_root(restarted, learn_sec=300, baseline_path=path)
    assert restarted.baseline_until <= time.time()
    assert (7, 9, "/usr/sbin/sshd") in restarted.baseline


def test_stale_baseline_learns_again(tmp_path, monkeypatch):
    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", lambda: set())
    path = tmp_path / "root_baseline.py.json"
    _write_baseline(
        path,
        int(time.time()) - 901,
        [{"pid": 111, "starttime": 1, "exe": "/usr/sbin/sshd"}],
    )
    state = RootWatchState()
    poll_new_root(state, learn_sec=300, baseline_path=path)
    assert state.baseline_until > time.time()
    assert (111, 1, "/usr/sbin/sshd") not in state.baseline


def test_baseline_symlink_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr("sysspectogram.root_watch.list_root_pids_cheap", lambda: set())
    real = tmp_path / "real.json"
    _write_baseline(
        real,
        int(time.time()),
        [{"pid": 7, "starttime": 8, "exe": "/usr/sbin/sshd"}],
    )
    link = tmp_path / "root_baseline.py.json"
    link.symlink_to(real)
    before = real.read_bytes()
    state = RootWatchState()
    poll_new_root(state, learn_sec=300, baseline_path=link)
    assert state.baseline_until > time.time()
    assert (7, 8, "/usr/sbin/sshd") not in state.baseline
    with pytest.raises(OSError):
        save_root_baseline(state, link)
    assert real.read_bytes() == before
    assert link.is_symlink()
