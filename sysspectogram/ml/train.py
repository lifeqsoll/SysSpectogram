from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from torch.utils.data import DataLoader, WeightedRandomSampler

from sysspectogram.ml.cnn import AnomalyCNN
from sysspectogram.ml.dataset import NpyWindowDataset
from sysspectogram.ml.ensemble import fuse_scores, pick_threshold
from sysspectogram.ml.forest import ForestDetector
from sysspectogram.preprocess.scaler import WindowScaler


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def train_models(
    dataset_dir: Path,
    out_dir: Path,
    epochs: int = 25,
    batch_size: int = 32,
    lr: float = 1e-3,
    seed: int = 42,
    cnn_weight: float = 0.55,
    iforest_weight: float = 0.45,
    recall_target: float = 0.85,
    device: str | None = None,
) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    out_dir.mkdir(parents=True, exist_ok=True)

    meta_path = dataset_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    window_size = int(meta.get("window_size", 60))
    n_features = int(meta.get("n_features", 30))

    train_ds = NpyWindowDataset(dataset_dir / "train")
    val_root = dataset_dir / "val"
    val_ds = NpyWindowDataset(val_root) if val_root.exists() and any(val_root.rglob("*.npy")) else None

    labels = [int(train_ds[i][2]) for i in range(len(train_ds))]
    class_count = np.bincount(labels, minlength=2).astype(np.float64)
    class_count[class_count == 0] = 1.0
    class_weights = (class_count.sum() / (2.0 * class_count)).astype(np.float32)
    sample_weights = [float(class_weights[y]) for y in labels]
    sampler = WeightedRandomSampler(sample_weights, num_samples=len(sample_weights), replacement=True)

    train_loader = DataLoader(train_ds, batch_size=batch_size, sampler=sampler)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False) if val_ds else None

    sample_x, _, _ = train_ds[0]
    height, width = int(sample_x.shape[1]), int(sample_x.shape[2])
    model = AnomalyCNN(height=height, width=width, dropout=0.3).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1))
    criterion = nn.CrossEntropyLoss(weight=torch.tensor(class_weights, device=device))

    best_state = None
    best_val_f1 = -1.0

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        n_batches = 0
        for xb, _, yb in train_loader:
            xb = xb.to(device)
            yb = yb.to(device)
            opt.zero_grad()
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            opt.step()
            total_loss += float(loss.item())
            n_batches += 1
        scheduler.step()
        avg = total_loss / max(n_batches, 1)

        # Quick val F1 on CNN alone for early model pick
        val_f1 = 0.0
        if val_loader is not None:
            model.eval()
            preds, trues = [], []
            with torch.no_grad():
                for xb, _, yb in val_loader:
                    logits = model(xb.to(device))
                    pred = torch.argmax(logits, dim=1).cpu().numpy()
                    preds.append(pred)
                    trues.append(yb.numpy())
            y_p = np.concatenate(preds)
            y_t = np.concatenate(trues)
            val_f1 = float(f1_score(y_t, y_p, zero_division=0))
            if val_f1 >= best_val_f1:
                best_val_f1 = val_f1
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        print(f"epoch {epoch}/{epochs} loss={avg:.4f} val_cnn_f1={val_f1:.4f}")

    if best_state is not None:
        model.load_state_dict(best_state)

    tab_list = []
    labels_list = []
    for _, tab, label in train_ds:
        tab_list.append(tab.numpy())
        labels_list.append(int(label))
    tab_x = np.stack(tab_list)
    tab_y = np.asarray(labels_list)
    normal_mask = tab_y == 0
    forest = ForestDetector(contamination=0.05, random_state=seed)
    forest.fit(tab_x[normal_mask] if np.any(normal_mask) else tab_x)

    def _collect(loader: DataLoader | None, ds: NpyWindowDataset | None):
        if loader is None or ds is None:
            return None
        model.eval()
        probs = []
        if_scores = []
        labels_out = []
        with torch.no_grad():
            for xb, tab, yb in loader:
                logits = model(xb.to(device))
                p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
                s = forest.anomaly_score(tab.numpy())
                probs.append(p)
                if_scores.append(s)
                labels_out.append(yb.numpy())
        return (
            np.concatenate(probs),
            np.concatenate(if_scores),
            np.concatenate(labels_out),
        )

    val_pack = _collect(val_loader, val_ds)
    if val_pack is None:
        raise RuntimeError(
            "validation set is empty; refuse to pick threshold on train "
            "(rebuild dataset with val_ratio>0 or more samples)"
        )
    cnn_p, if_s, y_true = val_pack
    fused = fuse_scores(cnn_p, if_s, cnn_weight, iforest_weight)
    if not isinstance(fused, np.ndarray):
        fused = np.asarray([fused])
    threshold = pick_threshold(fused, y_true, recall_target=recall_target)
    y_pred = (fused >= threshold).astype(int)
    metrics = _metrics(y_true, y_pred)

    torch.save(
        {
            "state_dict": model.state_dict(),
            "height": height,
            "width": width,
            "n_features": n_features,
            "window_size": window_size,
        },
        out_dir / "cnn.pt",
    )
    forest.save(out_dir / "iforest.joblib")

    scaler_src = dataset_dir / "scaler.joblib"
    if scaler_src.exists():
        WindowScaler.load(scaler_src).save(out_dir / "scaler.joblib")

    artifact_meta = {
        "columns": meta.get("columns", []),
        "window_size": window_size,
        "n_features": width,
        "height": height,
        "width": width,
        "threshold": threshold,
        "cnn_weight": cnn_weight,
        "iforest_weight": iforest_weight,
        "metrics": metrics,
        "best_val_cnn_f1": best_val_f1,
        "class_weights": class_weights.tolist(),
        "device_trained": device,
    }
    (out_dir / "meta.json").write_text(json.dumps(artifact_meta, indent=2), encoding="utf-8")
    import hashlib

    names = ["cnn.pt", "iforest.joblib", "scaler.joblib", "meta.json"]
    lines = []
    for name in names:
        f = out_dir / name
        if f.exists():
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {name}")
    (out_dir / "checksums.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    print(f"threshold={threshold:.4f}")
    return artifact_meta
