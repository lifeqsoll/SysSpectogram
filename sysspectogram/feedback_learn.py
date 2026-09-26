"""Persist operator feedback as labeled samples for fine-tune / threshold bias."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Literal

import numpy as np

Kind = Literal["baseline", "anomaly"]


class FeedbackLearner:
    """Writes windows + threshold bias so As normal / As anomaly affect future runs."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.normal_dir = self.root / "normal"
        self.anomaly_dir = self.root / "anomaly"
        self.meta_path = self.root / "meta.json"
        self.bias_path = self.root / "threshold_bias.json"
        self.normal_dir.mkdir(parents=True, exist_ok=True)
        self.anomaly_dir.mkdir(parents=True, exist_ok=True)

    def _meta(self) -> dict[str, Any]:
        if self.meta_path.exists():
            try:
                return json.loads(self.meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        return {"schema": "sysspectogram.feedback_learn.v1", "counts": {"baseline": 0, "anomaly": 0}}

    def _save_meta(self, meta: dict[str, Any]) -> None:
        self.meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    def threshold_bias(self) -> float:
        if not self.bias_path.exists():
            return 0.0
        try:
            data = json.loads(self.bias_path.read_text(encoding="utf-8"))
            return float(data.get("bias") or 0.0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return 0.0

    def _set_bias(self, delta: float) -> float:
        bias = self.threshold_bias() + float(delta)
        bias = max(-0.25, min(0.35, bias))
        self.bias_path.write_text(
            json.dumps({"bias": bias, "updated_at": time.time()}, indent=2) + "\n",
            encoding="utf-8",
        )
        return bias

    def record(
        self,
        kind: Kind,
        *,
        window: np.ndarray | None = None,
        columns: list[str] | None = None,
        score: float | None = None,
        process_key: str = "",
        note: str = "",
    ) -> dict[str, Any]:
        meta = self._meta()
        stamp = time.strftime("%Y%m%dT%H%M%S")
        dest_dir = self.normal_dir if kind == "baseline" else self.anomaly_dir
        row: dict[str, Any] = {
            "ts": time.time(),
            "kind": kind,
            "score": score,
            "process_key": process_key,
            "note": note,
        }
        if window is not None:
            name = f"{kind}_{stamp}_{meta['counts'].get(kind, 0):04d}"
            npy = dest_dir / f"{name}.npy"
            np.save(npy, np.asarray(window, dtype=np.float32))
            row["npy"] = str(npy.name)
            if columns:
                (dest_dir / f"{name}.columns.json").write_text(
                    json.dumps(columns) + "\n", encoding="utf-8"
                )
        (dest_dir / f"{kind}_{stamp}.json").write_text(
            json.dumps(row, indent=2) + "\n", encoding="utf-8"
        )
        meta["counts"][kind] = int(meta["counts"].get(kind, 0)) + 1
        self._save_meta(meta)
        # baseline -> raise decision threshold (fewer FP); anomaly -> lower (more sensitive)
        if kind == "baseline":
            bias = self._set_bias(0.02)
        else:
            bias = self._set_bias(-0.03)
        return {"ok": True, "kind": kind, "counts": meta["counts"], "threshold_bias": bias}

    def apply_bias(self, threshold: float) -> float:
        return float(threshold) + self.threshold_bias()

    def counts(self) -> dict[str, int]:
        return dict(self._meta().get("counts") or {})
