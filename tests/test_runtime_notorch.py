"""A0 runtime=notorch / optional torch."""

from __future__ import annotations

from pathlib import Path

import yaml

from sysspectogram.config import load_config


def test_default_runtime_notorch(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("SYSSPECTOGRAM_RUNTIME", raising=False)
    cfg = load_config()
    assert cfg.get("runtime") == "notorch"


def test_runtime_env_override(monkeypatch):
    monkeypatch.setenv("SYSSPECTOGRAM_RUNTIME", "onnx")
    cfg = load_config()
    assert cfg["runtime"] == "onnx"


def test_infer_import_without_eager_torch():
    import sysspectogram.ml.infer as infer_mod

    # Module must load even if we only need load_inferencer name
    assert hasattr(infer_mod, "load_inferencer")
    assert hasattr(infer_mod, "EnsembleInferencer")


def test_benign_sudo_helper():
    from sysspectogram.guard import _benign_sudo_sudoers

    assert _benign_sudo_sudoers("sudo", "/etc/sudoers")
    assert _benign_sudo_sudoers("sudo", "/etc/sudoers.d/foo")
    assert not _benign_sudo_sudoers("python", "/etc/sudoers")
    assert not _benign_sudo_sudoers("sudo", "/etc/passwd")
