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
