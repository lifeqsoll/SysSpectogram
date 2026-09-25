"""ONNX Runtime CNN + IsolationForest (no PyTorch on VPS)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from sysspectogram.ml.ensemble import fuse_scores
from sysspectogram.ml.forest import ForestDetector
from sysspectogram.ml.infer import Prediction
from sysspectogram.preprocess.heatmap import tabular_features, window_to_tensor
from sysspectogram.preprocess.scaler import WindowScaler


class OnnxEnsembleInferencer:
    def __init__(self, artifacts_dir: Path) -> None:
        try:
            import onnxruntime as ort
        except ImportError as exc:
            raise ImportError(
                "onnxruntime required. Install: pip install -e '.[onnx]'"
            ) from exc

        self.artifacts_dir = Path(artifacts_dir)
        onnx_path = self.artifacts_dir / "cnn.onnx"
        if not onnx_path.exists():
            raise FileNotFoundError(f"missing {onnx_path} — run export-onnx first")

        meta_path = self.artifacts_dir / "meta.json"
        self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.threshold = float(self.meta.get("threshold", 0.5))
        self.cnn_weight = float(self.meta.get("cnn_weight", 0.6))
        self.iforest_weight = float(self.meta.get("iforest_weight", 0.4))
        self.columns: list[str] = list(self.meta.get("columns", []))
        self.window_size = int(self.meta.get("window_size", 60))

        self.session = ort.InferenceSession(
            str(onnx_path), providers=["CPUExecutionProvider"]
        )
        self._input_name = self.session.get_inputs()[0].name
        self.forest = ForestDetector.load(self.artifacts_dir / "iforest.joblib")
        self.scaler = WindowScaler.load(self.artifacts_dir / "scaler.joblib")

    def predict_window(self, window: np.ndarray) -> Prediction:
        scaled = self.scaler.transform(window)
        tensor = window_to_tensor(scaled)[None, ...].astype(np.float32)
        logits = self.session.run(None, {self._input_name: tensor})[0]
        # softmax class 1
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        probs = e / e.sum(axis=1, keepdims=True)
        cnn_prob = float(probs[0, 1])
        if_score = float(self.forest.anomaly_score(tabular_features(scaled).reshape(1, -1))[0])
        score = float(fuse_scores(cnn_prob, if_score, self.cnn_weight, self.iforest_weight))
        return Prediction(
            score=score,
            cnn_prob=cnn_prob,
            iforest_score=if_score,
            is_anomaly=score >= self.threshold,
            threshold=self.threshold,
        )
