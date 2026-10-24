"""Friend wheel has no torch — importing ml / guard entrypoints must not require it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ml_package_imports_without_eager_torch_subprocess():
    """Lazy ml import in a subprocess — never pop torch from the pytest process."""
    code = r"""
import sys
for k in list(sys.modules):
    if k == "sysspectogram.ml" or k.startswith("sysspectogram.ml."):
        del sys.modules[k]
import sysspectogram.ml as ml
assert ml.Prediction is not None
assert callable(ml.load_inferencer)
assert "sysspectogram.ml.cnn" not in sys.modules
assert "sysspectogram.ml.train" not in sys.modules
assert "sysspectogram.ml.dataset" not in sys.modules
print("ok")
"""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "ok" in proc.stdout


def test_lockdown_refuses_empty_allow_without_nft(monkeypatch):
    from sysspectogram.response import actions as act

    monkeypatch.setattr(act.shutil, "which", lambda _name: None)
    nft = act.NftBackend(never_ban_cidrs=[])
    msg = nft.apply_lockdown(dry_run=False, allow_cidrs=[])
    assert "refused" in msg.lower() or "empty" in msg.lower()
