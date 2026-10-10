"""Event spectrogram: agent alerts as a 60 x K tensor for a small CNN (Phase 1b).

Windows are cut from a continuous per-second timeline, so quiet seconds are real
zeros and the time axis is consistent between normal and anomaly files.
Off by default: enabled with `agent.spectrogram: true` and only after the replay
in the test block shows a gain over the IF baseline (ADR 0002).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

from sysspectogram.agent_score import MATRIX_CHANNEL_CAP, MATRIX_CHANNELS, channel_for
from sysspectogram.incident.normalize import to_epoch

WINDOW = 60
STRIDE = 5
SCHEMA = "sysspectogram.agent_spectro.v1"


def _load_event_times(paths: Iterable[Path]) -> list[tuple[float, int]]:
    """Return (epoch_seconds, channel_index) for every alert in the JSONL files."""
    index = {c: i for i, c in enumerate(MATRIX_CHANNELS)}
    out: list[tuple[float, int]] = []
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("kind") == "metrics":
                continue
            ts = to_epoch(obj.get("ts"))
            if ts is None:
                continue
            ch = index.get(channel_for(str(obj.get("rule_id") or "")), index["other"])
            out.append((ts, ch))
    return out


def timeline_matrix(paths: Iterable[Path]) -> tuple[np.ndarray, float] | None:
    """Per-second counts over the whole span of the files. Returns (T x K, t0)."""
    events = _load_event_times(paths)
    if not events:
        return None
    t0 = min(ts for ts, _ in events)
    t1 = max(ts for ts, _ in events)
    n = int(t1 - t0) + 1
    grid = np.zeros((n, len(MATRIX_CHANNELS)), dtype=np.float64)
    for ts, ch in events:
        grid[int(ts - t0), ch] += 1.0
    return np.minimum(grid, MATRIX_CHANNEL_CAP), t0


def cut_windows(grid: np.ndarray, window: int = WINDOW, stride: int = STRIDE) -> np.ndarray:
    """Return (N, window, K) float32 windows, scaled to [0, 1] by the channel cap."""
    if grid.shape[0] < window:
        return np.zeros((0, window, grid.shape[1]), dtype=np.float32)
    starts = range(0, grid.shape[0] - window + 1, stride)
    arr = np.stack([grid[s : s + window] for s in starts]).astype(np.float32)
    return arr / float(MATRIX_CHANNEL_CAP)


def build_dataset(
    normal_paths: Sequence[Path], anomaly_paths: Sequence[Path]
) -> tuple[np.ndarray, np.ndarray]:
    xs: list[np.ndarray] = []
    ys: list[np.ndarray] = []
    for paths, label in ((normal_paths, 0), (anomaly_paths, 1)):
        built = timeline_matrix(paths)
        if built is None:
            continue
        w = cut_windows(built[0])
        xs.append(w)
        ys.append(np.full(w.shape[0], label, dtype=np.int64))
    if not xs:
        raise ValueError("no usable alert events in the given files")
    return np.concatenate(xs), np.concatenate(ys)


def train_event_cnn(
    normal_paths: Sequence[Path],
    anomaly_paths: Sequence[Path],
    out_dir: Path,
    *,
    epochs: int = 15,
    batch_size: int = 32,
    lr: float = 1e-3,
    seed: int = 42,
    val_ratio: float = 0.2,
    recall_target: float = 0.85,
) -> dict[str, Any]:
    """Train the event CNN and export `agent_spectro.onnx` plus `agent_spectro.meta.json`."""
    import torch
    import torch.nn.functional as F
    from torch.utils.data import DataLoader, TensorDataset

    from sysspectogram.ml.cnn import AnomalyCNN
    from sysspectogram.ml.ensemble import pick_threshold

    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    x, y = build_dataset(list(normal_paths), list(anomaly_paths))
    order = rng.permutation(len(x))
    x, y = x[order], y[order]
    n_val = max(1, int(len(x) * val_ratio))
    x_val, y_val = x[:n_val], y[:n_val]
    x_tr, y_tr = x[n_val:], y[n_val:]

    model = AnomalyCNN(height=WINDOW, width=len(MATRIX_CHANNELS), n_classes=2)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loader = DataLoader(
        TensorDataset(
            torch.from_numpy(x_tr[:, None, :, :]), torch.from_numpy(y_tr)
        ),
        batch_size=batch_size,
        shuffle=True,
    )
    model.train()
    for _ in range(int(epochs)):
        for xb, yb in loader:
            opt.zero_grad()
            loss = F.cross_entropy(model(xb), yb)
            loss.backward()
            opt.step()

    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(x_val[:, None, :, :]))
        probs = torch.softmax(logits, dim=1)[:, 1].numpy()
    threshold = float(pick_threshold(probs, y_val, recall_target=recall_target))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = out_dir / "agent_spectro.onnx"
    dummy = torch.zeros(1, 1, WINDOW, len(MATRIX_CHANNELS))
    torch.onnx.export(
        model,
        dummy,
        str(onnx_path),
        input_names=["input"],
        output_names=["logits"],
        dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=17,
    )
    meta = {
        "schema": SCHEMA,
        "channels": list(MATRIX_CHANNELS),
        "window": WINDOW,
        "stride": STRIDE,
        "channel_cap": MATRIX_CHANNEL_CAP,
        "threshold": threshold,
        "n_train": int(len(x_tr)),
        "n_val": int(len(x_val)),
        "seed": seed,
        "epochs": int(epochs),
    }
    (out_dir / "agent_spectro.meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return meta


class AgentSpectroScorer:
    """ONNX inference for the event spectrogram. Fails closed: no model means no score."""

    def __init__(self, model_dir: Path | None) -> None:
        self.session: Any | None = None
        self.meta: dict[str, Any] = {}
        if not model_dir:
            return
        onnx_path = Path(model_dir) / "agent_spectro.onnx"
        meta_path = Path(model_dir) / "agent_spectro.meta.json"
        if not onnx_path.is_file() or not meta_path.is_file():
            return
        import onnxruntime as ort

        self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if self.meta.get("channels") != list(MATRIX_CHANNELS):
            raise RuntimeError("agent_spectro channels do not match this build; re-train")
        self.session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
        self._input = self.session.get_inputs()[0].name

    @property
    def ready(self) -> bool:
        return self.session is not None

    def score(self, matrix: np.ndarray) -> float:
        """Probability of anomaly for one (window, K) matrix in raw counts."""
        if self.session is None:
            raise RuntimeError("agent spectrogram model not loaded")
        x = (np.asarray(matrix, dtype=np.float32) / float(MATRIX_CHANNEL_CAP))[None, None, :, :]
        logits = self.session.run(None, {self._input: x})[0]
        e = np.exp(logits - logits.max(axis=1, keepdims=True))
        return float((e / e.sum(axis=1, keepdims=True))[0, 1])
