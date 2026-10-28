"""Real nft named-set bans (F-01). Run under: sudo unshare -n pytest -m nft_real."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.nft_real


def _can_run_nft_real() -> bool:
    if os.geteuid() != 0:
        return False
    if not shutil.which("nft"):
        return False
    return True


skip_no_priv = pytest.mark.skipif(
    not _can_run_nft_real(),
    reason="needs root + nft (use: sudo unshare -n pytest -m nft_real)",
)


@skip_no_priv
def test_ban_ipv4_set_timeout_and_unban():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    msg = b.ban_ip("198.51.100.7", ttl_sec=60)
    assert msg.startswith("banned"), msg
    assert "backend=nft" in msg
    code, out = subprocess.run(
        ["nft", "list", "set", "inet", "sysspectogram", "ban4"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert code == 0, out
    assert "198.51.100.7" in out
    assert "expires" in out or "timeout" in out
    umsg = b.unban_ip("198.51.100.7")
    assert "unbanned" in umsg, umsg
    code2, out2 = subprocess.run(
        ["nft", "list", "set", "inet", "sysspectogram", "ban4"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert code2 == 0, out2
    assert "198.51.100.7" not in out2


@skip_no_priv
def test_ban_ipv6_set():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    msg = b.ban_ip("2001:db8::7", ttl_sec=60)
    assert msg.startswith("banned"), msg
    code, out = subprocess.run(
        ["nft", "list", "set", "inet", "sysspectogram", "ban6"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert code == 0, out
    assert "2001:db8::7" in out
    b.unban_ip("2001:db8::7")


@skip_no_priv
def test_rebban_updates_element():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    assert b.ban_ip("198.51.100.8", ttl_sec=60).startswith("banned")
    assert b.ban_ip("198.51.100.8", ttl_sec=120).startswith("banned")
    code, out = subprocess.run(
        ["nft", "list", "set", "inet", "sysspectogram", "ban4"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert code == 0
    assert out.count("198.51.100.8") == 1
    b.unban_ip("198.51.100.8")


@skip_no_priv
def test_never_ban_skip_no_element():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=["198.51.100.0/24"])
    msg = b.ban_ip("198.51.100.9", ttl_sec=60)
    assert "never_ban" in msg
    code, out = subprocess.run(
        ["nft", "list", "set", "inet", "sysspectogram", "ban4"],
        capture_output=True,
        text=True,
        check=False,
    )
    # table may exist from ensure; element must not
    if code == 0:
        assert "198.51.100.9" not in out


@skip_no_priv
def test_invalid_ip_never_calls_nft():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    calls: list[list[str]] = []
    real = b._run

    def wrap(cmd: list[str]):
        calls.append(list(cmd))
        return real(cmd)

    b._run = wrap  # type: ignore[method-assign]
    out = b.ban_ip("0.0.0.0/0", ttl_sec=60)
    assert out.startswith("refuse ban")
    assert not any("element" in c for c in calls)


@skip_no_priv
def test_ensure_table_idempotent():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    b._ensure_table()
    b._ensure_table()
    code, _ = subprocess.run(
        ["nft", "list", "table", "inet", "sysspectogram"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert code == 0


def test_ban_argv_uses_add_element_not_bare_comment(monkeypatch):
    """Unit: no unquoted comment with colon; prefer add element / -f -."""
    from sysspectogram.response.actions import NftBackend

    seen: list[list[str]] = []

    def fake_run(cmd: list[str]):
        seen.append(list(cmd))
        return 0, ""

    monkeypatch.setattr("sysspectogram.response.actions.shutil.which", lambda n: "/usr/sbin/nft" if n == "nft" else None)
    monkeypatch.setattr("sysspectogram.response.actions.os.geteuid", lambda: 0)
    b = NftBackend(never_ban_cidrs=[])
    monkeypatch.setattr(b, "_run", fake_run)
    monkeypatch.setattr(b, "_nft_stdin", lambda text: (0, ""))
    msg = b.ban_ip("198.51.100.10", ttl_sec=90)
    assert msg.startswith("banned")
    flat = " ".join(" ".join(c) for c in seen)
    # Must not pass bare comment sysspectogram:IP:TS as argv token
    assert not any(
        len(c) > 1 and c[-2] == "comment" and c[-1].startswith("sysspectogram:") for c in seen
    )
    assert "element" in flat or any(c[:2] == ["nft", "-f"] for c in seen)
