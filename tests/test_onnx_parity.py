"""Phase 7.9 — ONNX vs torch logits parity (skip if extras missing)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("torch") is None,
    reason="torch not installed",
)
def test_onnx_torch_parity_roundtrip(tmp_path: Path) -> None:
    ort = pytest.importorskip("onnxruntime")
    import torch

    from sysspectogram.ml.cnn import AnomalyCNN
    from sysspectogram.ml.export_onnx import export_cnn_onnx

    del ort
    h, w = 16, 12
    model = AnomalyCNN(height=h, width=w, n_classes=2)
    model.eval()
    art = tmp_path / "art"
    art.mkdir()
    ckpt = {
        "state_dict": model.state_dict(),
        "height": h,
        "width": w,
    }
    torch.save(ckpt, art / "cnn.pt")
    (art / "meta.json").write_text("{}", encoding="utf-8")
    export_cnn_onnx(art)
    assert (art / "cnn.onnx").is_file()

    x = torch.randn(1, 1, h, w)
    with torch.no_grad():
        torch_out = model(x).numpy()

    import onnxruntime as ort2

    sess = ort2.InferenceSession(str(art / "cnn.onnx"), providers=["CPUExecutionProvider"])
    onnx_out = sess.run(None, {"input": x.numpy()})[0]
    assert np.allclose(torch_out, onnx_out, atol=1e-4)
