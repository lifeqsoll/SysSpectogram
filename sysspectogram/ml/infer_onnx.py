"""ONNX Runtime CNN + IsolationForest (no PyTorch on VPS)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import numpy as np

from sysspectogram.ml.ensemble import fuse_scores
from sysspectogram.ml.infer import Prediction
from sysspectogram.preprocess.heatmap import tabular_features, window_to_tensor


class OnnxEnsembleInferencer:
    def __init__(
        self,
        artifacts_dir: Path,
        *,
        supply_chain: Mapping[str, Any] | None = None,
    ) -> None:
        from sysspectogram.supply_chain import open_verified_artifact, verify_artifacts

        policy = dict(supply_chain or {})
        self._supply_enforced = bool(policy.get("enforce", False))
        self._supply_manifest_name = str(
            policy.get("manifest_name") or "artifacts.manifest.json"
        )
        self._supply_signature_name = str(
            policy.get("signature_name") or "artifacts.manifest.json.minisig"
        )
        verify_artifacts(
            artifacts_dir,
            enforce=self._supply_enforced,
            public_key=policy.get("public_key"),
            manifest_name=self._supply_manifest_name,
            signature_name=self._supply_signature_name,
        )
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

        if self._supply_enforced:
            with open_verified_artifact(
                self.artifacts_dir,
                "cnn.onnx",
                manifest_name=self._supply_manifest_name,
                signature_name=self._supply_signature_name,
            ) as onnx_file:
                onnx_source: str | bytes = onnx_file.read()
        else:
            onnx_source = str(onnx_path)
        self.session = ort.InferenceSession(
            onnx_source, providers=["CPUExecutionProvider"]
        )
        self._input_name = self.session.get_inputs()[0].name
        from sysspectogram.safe_artifacts import load_forest_for_artifacts, load_scaler_for_artifacts

        self.forest = load_forest_for_artifacts(
            self.artifacts_dir,
            enforce=self._supply_enforced,
            open_verified=open_verified_artifact if self._supply_enforced else None,
            manifest_name=self._supply_manifest_name,
            signature_name=self._supply_signature_name,
        )
        self.scaler = load_scaler_for_artifacts(
            self.artifacts_dir,
            enforce=self._supply_enforced,
            open_verified=open_verified_artifact if self._supply_enforced else None,
            manifest_name=self._supply_manifest_name,
            signature_name=self._supply_signature_name,
        )

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
