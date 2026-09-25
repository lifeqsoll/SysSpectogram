"""Export AnomalyCNN cnn.pt → cnn.onnx (builder machine with torch)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_cnn_onnx(
    artifacts_dir: Path,
    *,
    out_path: Path | None = None,
    opset: int = 17,
) -> dict[str, Any]:
    try:
        import torch
    except ImportError as exc:
        raise ImportError("export-onnx needs PyTorch: pip install -e '.[ml]'") from exc

    from sysspectogram.ml.cnn import AnomalyCNN

    artifacts_dir = Path(artifacts_dir)
    out_path = Path(out_path) if out_path else artifacts_dir / "cnn.onnx"
    ckpt_path = artifacts_dir / "cnn.pt"
    if not ckpt_path.exists():
        raise FileNotFoundError(ckpt_path)

    try:
        ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=True)
    except TypeError:
        ckpt = torch.load(ckpt_path, map_location="cpu")
    except Exception:
        ckpt = torch.load(ckpt_path, map_location="cpu", weights_only=False)

    if not isinstance(ckpt, dict) or "state_dict" not in ckpt:
        raise RuntimeError("cnn.pt missing state_dict")
    height = int(ckpt["height"])
    width = int(ckpt["width"])
    model = AnomalyCNN(height=height, width=width)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    dummy = torch.zeros(1, 1, height, width)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.onnx.export(
        model,
        dummy,
        str(out_path),
        input_names=["input"],
        output_names=["logits"],
        dynamic_axes=None,
        opset_version=opset,
    )

    meta_path = artifacts_dir / "meta.json"
    meta: dict[str, Any] = {}
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["infer_backend"] = "onnx"
    meta["onnx_file"] = out_path.name
    meta["cnn_height"] = height
    meta["cnn_width"] = width
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    # refresh checksums so torch infer still loads
    import hashlib

    lines = []
    for name in ("cnn.pt", "cnn.onnx", "iforest.joblib", "scaler.joblib", "meta.json"):
        f = artifacts_dir / name
        if f.exists():
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            lines.append(f"{h}  {name}")
    (artifacts_dir / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "onnx": str(out_path.resolve()),
        "height": height,
        "width": width,
        "meta": str(meta_path.resolve()),
    }
