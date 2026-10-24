from __future__ import annotations

from sysspectogram.response.actions import NftBackend


def test_quarantine_dry_run():
    nft = NftBackend(never_ban_cidrs=["203.0.113.1/32"])
    msg = nft.quarantine_ports([80, 443], dry_run=True)
    assert "dry-run" in msg and "80" in msg
    assert "dry-run" in nft.release_quarantine(dry_run=True)
    assert "dry-run" in nft.release_lockdown(dry_run=True)
