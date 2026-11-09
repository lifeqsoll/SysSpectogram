"""nft comment argv must be quoted so colons are not syntax errors."""

from __future__ import annotations

import shutil

import pytest

from sysspectogram.response.actions import NftBackend


def test_nft_comment_helper_quotes_and_strips() -> None:
    assert NftBackend._nft_comment('sysspectogram:port:22:1') == '"sysspectogram:port:22:1"'
    assert '"' not in NftBackend._nft_comment('a"b\nc').strip('"')


def test_lockdown_argv_comments_are_quoted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(list(argv))
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["203.0.113.10/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    msg = nft.apply_lockdown(dry_run=False)
    assert "failed" not in msg.lower() and "refused" not in msg.lower()
    comment_args = []
    for c in calls:
        if "comment" in c:
            i = c.index("comment")
            comment_args.append(c[i + 1])
    assert comment_args
    for tok in comment_args:
        assert tok.startswith('"') and tok.endswith('"'), tok
        assert "sysspectogram:" in tok
    syn = [c for c in calls if "lockdown:syn" in " ".join(c)]
    assert syn
    argv = syn[0]
    i = argv.index("flags")
    assert argv[i : i + 4] == ["flags", "syn", "/", "fin,syn,rst,ack"]


def test_lockdown_rolls_back_when_syn_rule_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    rules: list[str] = []

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(list(argv))
        if "fin,syn,rst,ack" in argv:
            return 1, "syntax error"
        if argv[:2] == ["nft", "-a"]:
            return 0, "\n".join(f'{r} # handle {i+1}' for i, r in enumerate(rules))
        if "comment" in argv:
            rules.append(argv[argv.index("comment") + 1].strip('"'))
            return 0, ""
        if "delete" in argv and "handle" in argv:
            return 0, ""
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["203.0.113.10/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    msg = nft.apply_lockdown(dry_run=False)
    assert "failed" in msg.lower()
    assert any("delete" in c and "handle" in c for c in calls)


def test_synrl_failure_does_not_remove_lockdown(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []
    rules = [
        'comment "sysspectogram:lockdown:est"',
        'comment "sysspectogram:lockdown:allow:203.0.113.10/32"',
        'comment "sysspectogram:lockdown:syn"',
    ]

    def fake_run(argv: list[str]) -> tuple[int, str]:
        if "limit" in argv:
            return 1, "forced"
        if argv[:2] == ["nft", "-a"]:
            return 0, "\n".join(f"{r} # handle {i+1}" for i, r in enumerate(rules))
        if "delete" in argv and "handle" in argv:
            deleted.append(argv[-1])
            return 0, ""
        if "comment" in argv:
            rules.append(argv[argv.index("comment") + 1])
            return 0, ""
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["203.0.113.10/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    msg = nft.apply_syn_rate_limit()
    assert "failed" in msg.lower()
    assert deleted
    assert "1" not in deleted and "2" not in deleted and "3" not in deleted


def test_lockdown_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    adds = 0

    def fake_run(argv: list[str]) -> tuple[int, str]:
        nonlocal adds
        if argv[:2] == ["nft", "-a"]:
            if adds:
                return 0, (
                    'comment "sysspectogram:lockdown:est" # handle 1\n'
                    'comment "sysspectogram:lockdown:allow:203.0.113.10/32" # handle 2\n'
                    'comment "sysspectogram:lockdown:syn" # handle 3\n'
                )
            return 0, ""
        if argv[:3] == ["nft", "add", "rule"]:
            adds += 1
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["203.0.113.10/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    assert "failed" not in nft.apply_lockdown().lower()
    first = adds
    assert "failed" not in nft.apply_lockdown().lower()
    assert adds == first


def test_second_lockdown_inserts_allow_before_syn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    listing = (
        'ip saddr 192.0.2.11 accept comment "sysspectogram:lockdown:allow:192.0.2.11/32" # handle 2\n'
        'tcp flags & (fin | syn | rst | ack) == syn drop comment "sysspectogram:lockdown:syn" # handle 3\n'
    )

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(list(argv))
        if argv[:2] == ["nft", "-a"]:
            return 0, listing
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["192.0.2.11/32", "203.0.113.7/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    msg = nft.apply_lockdown()
    assert "203.0.113.7/32" in msg
    inserted = [c for c in calls if c[:3] == ["nft", "insert", "rule"]]
    assert inserted
    assert inserted[0][inserted[0].index("position") + 1] == "3"
    joined = " ".join(inserted[0])
    assert "203.0.113.7/32" in joined
    assert "lockdown:syn" not in joined


def test_synrl_allow_inserts_before_drop_and_rate_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    listing = (
        'ip saddr 192.0.2.11 accept comment "sysspectogram:synrl:allow:192.0.2.11/32" # handle 4\n'
        "tcp flags & (fin | syn | rst | ack) == syn limit rate over 25/second burst 50 packets "
        'drop comment "sysspectogram:synrl:drop" # handle 5\n'
    )

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(list(argv))
        if argv[:2] == ["nft", "-a"]:
            return 0, listing
        return 0, ""

    nft = NftBackend(never_ban_cidrs=["192.0.2.11/32", "203.0.113.7/32"])
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(nft, "_ensure_chain", lambda: None)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    same = nft.apply_syn_rate_limit(rate="25/second", burst=50)
    assert "unchanged" not in same
    assert "25/second" in same
    assert not any(c[:2] == ["nft", "replace"] for c in calls)
    msg = nft.apply_syn_rate_limit(rate="10/second", burst=10)
    assert "10/second" in msg
    assert "unchanged" not in msg
    replaced = [c for c in calls if c[:2] == ["nft", "replace"]]
    assert replaced and "10/second" in replaced[0]
    inserted = [c for c in calls if c[:3] == ["nft", "insert", "rule"]]
    assert inserted
    assert inserted[0][inserted[0].index("position") + 1] == "5"


def test_shield_argv_comment_quoted(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str]) -> tuple[int, str]:
        calls.append(list(argv))
        return 0, ""

    nft = NftBackend()
    monkeypatch.setattr(nft, "_run", fake_run)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    nft.shield_port(8080, ttl_sec=60)
    matched = [c for c in calls if "comment" in c]
    assert matched
    tok = matched[0][matched[0].index("comment") + 1]
    assert tok.startswith('"') and tok.endswith('"')
    assert "sysspectogram:port:8080:" in tok


@pytest.mark.skipif(not shutil.which("nft"), reason="nft binary required")
@pytest.mark.skipif(__import__("os").geteuid() != 0, reason="root required for live nft")
def test_live_lockdown_roundtrip_when_root() -> None:
    nft = NftBackend(never_ban_cidrs=["203.0.113.10/32"])
    msg = nft.apply_lockdown(dry_run=False)
    assert "failed" not in msg.lower()
    code, out = nft._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
    assert code == 0
    assert "sysspectogram:lockdown:est" in out
    assert "sysspectogram:lockdown:syn" in out
    rel = nft.release_lockdown(dry_run=False) if hasattr(nft, "release_lockdown") else ""
    _ = rel
    nft.apply_lockdown(dry_run=False)
    nft.apply_lockdown(dry_run=False)
    code, out = nft._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
    assert out.count("sysspectogram:lockdown:est") == 1
    real = nft._run

    def wrapped(argv: list[str]) -> tuple[int, str]:
        if "limit" in argv:
            return 1, "forced fail"
        return real(argv)

    nft._run = wrapped  # type: ignore[method-assign]
    msg = nft.apply_syn_rate_limit()
    assert "failed" in msg.lower()
    code, out = real(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
    assert "sysspectogram:lockdown:est" in out
    assert "sysspectogram:synrl:" not in out
    nft._run = real  # type: ignore[method-assign]
    nft.release_lockdown(dry_run=False)


@pytest.mark.skipif(not shutil.which("nft"), reason="nft binary required")
@pytest.mark.skipif(__import__("os").geteuid() != 0, reason="root required for live nft")
def test_live_second_lockdown_allow_before_drop() -> None:
    nft = NftBackend(never_ban_cidrs=["192.0.2.11/32"])
    try:
        first = nft.apply_lockdown(dry_run=False)
        assert "failed" not in first.lower()
        nft.never_ban_cidrs = ["192.0.2.11/32", "203.0.113.7/32"]
        second = nft.apply_lockdown(dry_run=False)
        assert "203.0.113.7/32" in second
        assert "failed" not in second.lower()
        code, out = nft._run(["nft", "-a", "list", "chain", "inet", "sysspectogram", "input"])
        assert code == 0
        allow_at = out.find("sysspectogram:lockdown:allow:203.0.113.7/32")
        drop_at = out.find("sysspectogram:lockdown:syn")
        assert allow_at != -1 and drop_at != -1
        assert allow_at < drop_at
    finally:
        nft.release_lockdown(dry_run=False)
