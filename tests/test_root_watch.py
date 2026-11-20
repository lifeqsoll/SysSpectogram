"""Root process watch tests."""

from __future__ import annotations

from sysspectogram.root_watch import (
    DEFAULT_ALLOW_COMMS,
    RootWatchState,
    list_root_procs,
    pid_under_trusted,
    poll_new_root,
    root_severity,
    soft_allow,
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
    for name in ("journalctl", "systemctl", "nft", "ip", "ss", "pacman", "sudo", "fstrim"):
        assert name in DEFAULT_ALLOW_COMMS


def test_soft_allow_utilities_need_system_exe():
    assert soft_allow("journalctl", "/usr/bin/journalctl", set(DEFAULT_ALLOW_COMMS))
    assert not soft_allow("journalctl", "/tmp/journalctl", set(DEFAULT_ALLOW_COMMS))
    assert soft_allow("sudo", "/usr/bin/sudo", set(DEFAULT_ALLOW_COMMS))


def test_sudo_child_not_auto_allowed_by_parent_name():
    # A random root binary is not soft-allowed even if parent was sudo.
    assert not soft_allow("evil", "/tmp/evil", set(DEFAULT_ALLOW_COMMS))


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
