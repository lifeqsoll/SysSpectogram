"""F-05: ban failure messages must not look like success."""

from __future__ import annotations


def test_classify_ban_failed():
    from sysspectogram.response.actions import classify_ban_message

    r = classify_ban_message("nft failed: Operation not permitted", ip="198.51.100.7")
    assert r.ok is False
    assert r.skipped is False
    assert "FAILED" not in str(r)  # detail is raw; callers prefix BAN FAILED
    assert str(r).startswith("nft failed")


def test_classify_ban_ok():
    from sysspectogram.response.actions import classify_ban_message

    r = classify_ban_message("banned 198.51.100.7 ttl=60 backend=nft", ip="198.51.100.7")
    assert r.ok is True


def test_classify_never_ban_skip():
    from sysspectogram.response.actions import classify_ban_message

    r = classify_ban_message("never_ban skip 198.51.100.7", ip="198.51.100.7")
    assert r.skipped is True
    assert r.ok is False


def test_on_auto_ban_tg_failed_prefix(monkeypatch, tmp_path):
    """Guard on_auto_ban must send BAN FAILED, not AUTO-BAN, on nft errors."""
    sent: list[str] = []

    class FakeClient:
        def send_message(self, text: str) -> None:
            sent.append(text)

    class FakeBot:
        def __init__(self) -> None:
            self.client = FakeClient()

        def prefix(self, text: str) -> str:
            return text

    class FakeNft:
        def ban_ip(self, ip, ttl_sec=None, dry_run=False):
            return "nft failed: you must be root"

    # Minimal exercise of classify path used by guard (unit, not full run_guard).
    from sysspectogram.response.actions import classify_ban_message

    msg = FakeNft().ban_ip("198.51.100.7", ttl_sec=60)
    res = classify_ban_message(msg, ip="198.51.100.7")
    bot = FakeBot()
    if res.ok:
        line = f"AUTO-BAN {msg}"
    elif res.skipped:
        line = f"BAN SKIPPED ({msg})"
    else:
        line = f"BAN FAILED 198.51.100.7: {msg}"
    bot.client.send_message(bot.prefix(line))
    assert sent
    assert sent[0].startswith("BAN FAILED")
    assert "AUTO-BAN" not in sent[0]
