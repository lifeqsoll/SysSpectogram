"""Friend wheel has no torch — importing ml / guard entrypoints must not require it."""

from __future__ import annotations

import sys


def test_ml_package_imports_without_eager_torch():
    """Package import must stay lazy: cnn/train/dataset must not load at import time.

    Do not pop ``torch`` from ``sys.modules`` — that leaves C++ TORCH_LIBRARY
    registrations and breaks later ``import torch`` (triton double-register / segfault).
    No-torch CI job covers a real torch-free env.
    """
    for key in list(sys.modules):
        if key == "sysspectogram.ml" or key.startswith("sysspectogram.ml."):
            del sys.modules[key]

    import sysspectogram.ml as ml

    assert ml.Prediction is not None
    assert callable(ml.load_inferencer)
    assert "sysspectogram.ml.cnn" not in sys.modules
    assert "sysspectogram.ml.train" not in sys.modules
    assert "sysspectogram.ml.dataset" not in sys.modules


def test_lockdown_refuses_empty_allow_without_nft(monkeypatch):
    from sysspectogram.response import actions as act

    monkeypatch.setattr(act.shutil, "which", lambda _name: None)
    nft = act.NftBackend(never_ban_cidrs=[])
    msg = nft.apply_lockdown(dry_run=False, allow_cidrs=[])
    assert "refused" in msg.lower() or "empty" in msg.lower()
