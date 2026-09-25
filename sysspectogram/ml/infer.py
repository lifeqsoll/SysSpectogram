from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from sysspectogram.ml.ensemble import fuse_scores
from sysspectogram.ml.forest import ForestDetector
from sysspectogram.preprocess.heatmap import tabular_features, window_to_tensor
from sysspectogram.preprocess.scaler import WindowScaler


@dataclass
class Prediction:
    score: float
    cnn_prob: float
    iforest_score: float
    is_anomaly: bool
    threshold: float


class _InferBackend(Protocol):
    columns: list[str]
    window_size: int
    threshold: float

    def predict_window(self, window: np.ndarray) -> Prediction: ...


def load_inferencer(
    artifacts_dir: Path,
    *,
    runtime: str = "torch_ml",
    device: str | None = None,
) -> _InferBackend:
    """Pick backend: notorch raises; onnx prefers cnn.onnx; torch_ml uses cnn.pt."""
    artifacts_dir = Path(artifacts_dir)
    runtime = (runtime or "torch_ml").strip().lower()
    if runtime == "notorch":
        raise RuntimeError("runtime=notorch — host CNN disabled")
    onnx_path = artifacts_dir / "cnn.onnx"
    if runtime == "onnx" or (runtime != "torch_ml" and onnx_path.exists()):
        from sysspectogram.ml.infer_onnx import OnnxEnsembleInferencer

        return OnnxEnsembleInferencer(artifacts_dir)
    return EnsembleInferencer(artifacts_dir, device=device)


class EnsembleInferencer:
    """Torch CNN + IsolationForest (requires torch / pip install -e '.[ml]')."""

    def __init__(self, artifacts_dir: Path, device: str | None = None) -> None:
        try:
            import torch
        except ImportError as exc:
            raise ImportError(
                "PyTorch required for cnn.pt inference. "
                "Install: pip install -e '.[ml]'  — or export-onnx and use runtime=onnx"
            ) from exc

        from sysspectogram.ml.cnn import AnomalyCNN

        self.artifacts_dir = Path(artifacts_dir)
        meta_path = self.artifacts_dir / "meta.json"
        self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.threshold = float(self.meta.get("threshold", 0.5))
        self.cnn_weight = float(self.meta.get("cnn_weight", 0.6))
        self.iforest_weight = float(self.meta.get("iforest_weight", 0.4))
        self.columns: list[str] = list(self.meta.get("columns", []))
        self.window_size = int(self.meta.get("window_size", 60))
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._torch = torch

        try:
            ckpt = torch.load(
                self.artifacts_dir / "cnn.pt",
                map_location=self.device,
                weights_only=True,
            )
        except TypeError:
            ckpt = torch.load(self.artifacts_dir / "cnn.pt", map_location=self.device)
        except Exception:
            ckpt = torch.load(
                self.artifacts_dir / "cnn.pt",
                map_location=self.device,
                weights_only=False,
            )
        if isinstance(ckpt, dict) and "state_dict" in ckpt:
            height, width = ckpt["height"], ckpt["width"]
            state = ckpt["state_dict"]
        else:
            raise RuntimeError("cnn.pt missing state_dict")
        self.model = AnomalyCNN(height=height, width=width)
        self.model.load_state_dict(state)
        self.model.to(self.device)
        self.model.eval()

        checksum_path = self.artifacts_dir / "checksums.sha256"
        if checksum_path.exists():
            self._verify_checksums(checksum_path)

        self.forest = ForestDetector.load(self.artifacts_dir / "iforest.joblib")
        self.scaler = WindowScaler.load(self.artifacts_dir / "scaler.joblib")

    def _verify_checksums(self, path: Path) -> None:
        import hashlib

        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            expect, name = parts[0], parts[-1]
            f = self.artifacts_dir / name
            if not f.exists():
                raise RuntimeError(f"missing artifact {name} for checksum")
            h = hashlib.sha256(f.read_bytes()).hexdigest()
            if h != expect:
                raise RuntimeError(f"checksum mismatch for {name}")

    def predict_window(self, window: np.ndarray) -> Prediction:
        torch = self._torch
        scaled = self.scaler.transform(window)
        tensor = torch.from_numpy(window_to_tensor(scaled)).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            cnn_prob = float(torch.softmax(logits, dim=1)[0, 1].cpu())
        if_score = float(self.forest.anomaly_score(tabular_features(scaled).reshape(1, -1))[0])
        score = float(fuse_scores(cnn_prob, if_score, self.cnn_weight, self.iforest_weight))
        is_anomaly = score >= self.threshold
        return Prediction(
            score=score,
            cnn_prob=cnn_prob,
            iforest_score=if_score,
            is_anomaly=is_anomaly,
            threshold=self.threshold,
        )
