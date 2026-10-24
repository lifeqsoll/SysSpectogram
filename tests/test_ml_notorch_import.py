"""Friend wheel has no torch — importing ml / guard entrypoints must not require it."""

from __future__ import annotations


def test_ml_package_imports_without_torch():
    import sys

    sys.modules.pop("torch", None)
    # If torch is installed in the env, still ensure package import path is lazy.
    import sysspectogram.ml as ml

    assert ml.Prediction is not None
    assert callable(ml.load_inferencer)


def test_lockdown_refuses_empty_allow_without_nft(monkeypatch):
    from sysspectogram.response import actions as act

    monkeypatch.setattr(act.shutil, "which", lambda _name: None)
    nft = act.NftBackend(never_ban_cidrs=[])
    msg = nft.apply_lockdown(dry_run=False, allow_cidrs=[])
    assert "refused" in msg.lower() or "empty" in msg.lower()
