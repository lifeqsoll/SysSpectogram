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


def _nft(argv: list[str]) -> tuple[int, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


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
    code, out = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban4"])
    assert code == 0, out
    assert "198.51.100.7" in out
    assert "expires" in out or "timeout" in out
    umsg = b.unban_ip("198.51.100.7")
    assert "unbanned" in umsg, umsg
    code2, out2 = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban4"])
    assert code2 == 0, out2
    assert "198.51.100.7" not in out2


@skip_no_priv
def test_ban_ipv6_set():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    msg = b.ban_ip("2001:db8::7", ttl_sec=60)
    assert msg.startswith("banned"), msg
    code, out = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban6"])
    assert code == 0, out
    assert "2001:db8::7" in out
    b.unban_ip("2001:db8::7")


@skip_no_priv
def test_ban_ipv6_prefix_64():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    msg = b.ban_ip("2001:db8:1::/64", ttl_sec=60)
    assert msg.startswith("banned"), msg
    code, out = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban6"])
    assert code == 0, out
    assert "2001:db8:1::/64" in out or "2001:db8:1::" in out
    b.unban_ip("2001:db8:1::/64")


@skip_no_priv
def test_v6_gateway_protected_live(monkeypatch):
    from sysspectogram.response.actions import NftBackend
    from sysspectogram.response import protect
    import pytest

    def _ip(argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, check=False, capture_output=True, text=True)

    # veth works without the dummy kernel module.
    r = _ip(["ip", "link", "add", "v0", "type", "veth", "peer", "name", "v1"])
    if r.returncode != 0:
        pytest.skip("veth unavailable")
    _ip(["ip", "link", "set", "v0", "up"])
    _ip(["ip", "link", "set", "v1", "up"])
    _ip(["ip", "-6", "addr", "add", "2001:db8:feed::1/64", "dev", "v0", "nodad"])
    _ip(["ip", "-6", "route", "add", "default", "via", "2001:db8:feed::fffe", "dev", "v0"])
    out = _ip(["ip", "-6", "-o", "route", "show", "default"]).stdout
    if "2001:db8:feed::fffe" not in out:
        pytest.skip("could not install v6 default route")
    monkeypatch.setattr(protect, "_host_addrs", lambda: set())
    monkeypatch.setattr(protect, "_ssh_session_ips", lambda **k: set())
    monkeypatch.setattr(protect, "_resolver_addrs", lambda: set())
    b = NftBackend(never_ban_cidrs=[])
    msg = b.ban_ip("2001:db8:feed::fffe", ttl_sec=60)
    assert "protected" in msg or "refuse" in msg, msg
    code, listed = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban6"])
    if code == 0:
        assert "2001:db8:feed::fffe" not in listed


@skip_no_priv
def test_rebban_updates_element():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=[])
    assert b.ban_ip("198.51.100.8", ttl_sec=60).startswith("banned")
    assert b.ban_ip("198.51.100.8", ttl_sec=120).startswith("banned")
    code, out = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban4"])
    assert code == 0
    assert out.count("198.51.100.8") == 1
    b.unban_ip("198.51.100.8")


@skip_no_priv
def test_never_ban_skip_no_element():
    from sysspectogram.response.actions import NftBackend

    b = NftBackend(never_ban_cidrs=["198.51.100.0/24"])
    msg = b.ban_ip("198.51.100.9", ttl_sec=60)
    assert "never_ban" in msg
    code, out = _nft(["nft", "list", "set", "inet", "sysspectogram", "ban4"])
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
    code, _ = _nft(["nft", "list", "table", "inet", "sysspectogram"])
    assert code == 0


def test_migrate_ban6_adds_interval(monkeypatch):
    from sysspectogram.response.actions import NftBackend

    stdin_scripts: list[str] = []

    def fake_run(cmd: list[str]) -> tuple[int, str]:
        if cmd[:5] == ["nft", "list", "set", "inet", "sysspectogram"]:
            return (
                0,
                "set ban6 { type ipv6_addr; flags timeout; elements = { "
                "2001:db8::7 timeout 90s } }",
            )
        if cmd[:4] == ["nft", "-j", "list", "set"]:
            return (
                0,
                '[{"nftables":[{"set":{"elem":[{"elem":{"val":"2001:db8::7","timeout":90}}]}}]}]',
            )
        return 0, ""

    b = NftBackend(never_ban_cidrs=[])
    monkeypatch.setattr(b, "_run", fake_run)
    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which", lambda n: "/usr/sbin/nft" if n == "nft" else None
    )
    monkeypatch.setattr(b, "_nft_stdin", lambda text: stdin_scripts.append(text) or (0, ""))
    b._migrate_ban6()
    assert stdin_scripts
    script = stdin_scripts[0]
    assert "interval,timeout" in script
    assert "2001:db8::7" in script


def test_migrate_ban6_empty_json_falls_back_to_text(monkeypatch):
    """Empty nft -j list must not drop members — fall back to text parse of list out."""
    from sysspectogram.response.actions import NftBackend

    stdin_scripts: list[str] = []

    def fake_run(cmd: list[str]) -> tuple[int, str]:
        if cmd[:5] == ["nft", "list", "set", "inet", "sysspectogram"]:
            return (
                0,
                "set ban6 { type ipv6_addr; flags timeout; elements = { "
                "2001:db8::7 timeout 90s } }",
            )
        if cmd[:4] == ["nft", "-j", "list", "set"]:
            return 0, "[]"
        return 0, ""

    b = NftBackend(never_ban_cidrs=[])
    monkeypatch.setattr(b, "_run", fake_run)
    monkeypatch.setattr(
        "sysspectogram.response.actions.shutil.which",
        lambda n: "/usr/sbin/nft" if n == "nft" else None,
    )
    monkeypatch.setattr(b, "_nft_stdin", lambda text: stdin_scripts.append(text) or (0, ""))
    b._migrate_ban6()
    assert stdin_scripts
    script = stdin_scripts[0]
    assert "interval,timeout" in script
    assert "2001:db8::7" in script


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


def test_gateway_parses_via_inet6():
    from sysspectogram.response.protect import _parse_route_gateways

    text = "default nexthop via inet6 2001:db8::1 dev v0 weight 1"
    assert "2001:db8::1" in _parse_route_gateways(text)
