"""fleet keyscan / ssh destination parsing (IPv6, port, injection)."""

from __future__ import annotations

from unittest.mock import patch

from sysspectogram.fleet.pair import keyscan_argv, parse_ssh_host_port, suggest_keyscan
from sysspectogram.fleet.ssh import _ssh_base_args, parse_ssh_destination
from sysspectogram.fleet.store import FleetHost


def test_parse_user_host():
    assert parse_ssh_host_port("alice@example.com") == ("example.com", None)


def test_parse_user_host_port():
    assert parse_ssh_host_port("alice@example.com:2222") == ("example.com", 2222)


def test_parse_bracketed_ipv6_port():
    assert parse_ssh_host_port("alice@[2001:db8::1]:2222") == ("2001:db8::1", 2222)
    d = parse_ssh_destination("root@[::1]:2222")
    assert d is not None
    assert d.host == "::1"
    assert d.port == 2222
    assert d.ssh_argv_dest() == "root@::1"


def test_parse_bracketed_ipv6():
    assert parse_ssh_host_port("alice@[2001:db8::1]") == ("2001:db8::1", None)


def test_parse_bare_ipv6():
    assert parse_ssh_host_port("root@2001:db8::7") == ("2001:db8::7", None)


def test_parse_rejects_option_injection():
    assert parse_ssh_host_port("-oProxyCommand=evil") is None
    assert parse_ssh_host_port("user@-oProxyCommand=evil") is None
    assert parse_ssh_host_port("") is None


def test_keyscan_argv_ipv6_no_brackets():
    argv = keyscan_argv("root@[::1]:2222", keyscan_bin="/usr/bin/ssh-keyscan")
    assert argv == ["/usr/bin/ssh-keyscan", "-T", "5", "-t", "ed25519,rsa", "-p", "2222", "::1"]


def test_keyscan_argv_host_port():
    argv = keyscan_argv("alice@vps.example:2200", keyscan_bin="ssh-keyscan")
    assert argv == ["ssh-keyscan", "-T", "5", "-t", "ed25519,rsa", "-p", "2200", "vps.example"]


def test_suggest_keyscan_rejects_injection():
    out = suggest_keyscan("-oProxyCommand=evil")
    assert out["ok"] is False
    assert out.get("host") is None


def test_suggest_keyscan_passes_bare_ipv6(monkeypatch):
    class FakeProc:
        stdout = "# comment\n::1 ssh-ed25519 AAAA\n"
        stderr = ""
        returncode = 0

    with patch("shutil.which", return_value="/bin/ssh-keyscan"):
        with patch("subprocess.run", return_value=FakeProc()) as run:
            out = suggest_keyscan("root@[::1]:2222")
    assert out["ok"] is True
    assert out["argv"][-1] == "::1"
    assert "-p" in out["argv"] and "2222" in out["argv"]
    assert run.call_args.args[0][-1] == "::1"
    assert "[" not in run.call_args.args[0][-1]


def test_ssh_run_uses_dash_p_not_colon_in_dest():
    host = FleetHost(id="h", label="h", ssh="alice@example.com:2222", host_key_line="ssh-ed25519 AAAA")
    parsed = parse_ssh_destination(host.ssh)
    assert parsed is not None
    cmd, known = _ssh_base_args(host, parsed=parsed)
    assert "-p" in cmd and "2222" in cmd
    assert parsed.ssh_argv_dest() == "alice@example.com"
    assert parsed.known_hosts_name() == "[example.com]:2222"
    if known is not None:
        known.unlink(missing_ok=True)


def test_known_hosts_port_22_no_brackets():
    d = parse_ssh_destination("alice@example.com:22")
    assert d is not None
    assert d.known_hosts_name() == "example.com"
    d6 = parse_ssh_destination("root@[::1]")
    assert d6 is not None
    assert d6.known_hosts_name() == "::1"


def test_known_hosts_ipv6_with_nondefault_port():
    d = parse_ssh_destination("root@[2001:db8::1]:2222")
    assert d is not None
    assert d.known_hosts_name() == "[2001:db8::1]:2222"
