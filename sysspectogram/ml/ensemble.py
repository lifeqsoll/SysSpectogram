from __future__ import annotations

import numpy as np


def fuse_scores(
    cnn_prob: float | np.ndarray,
    iforest_score: float | np.ndarray,
    cnn_weight: float = 0.6,
    iforest_weight: float = 0.4,
) -> float | np.ndarray:
    total = cnn_weight + iforest_weight
    w_cnn = cnn_weight / total
    w_if = iforest_weight / total
    return w_cnn * cnn_prob + w_if * iforest_score


def pick_threshold(
    scores: np.ndarray,
    labels: np.ndarray,
    recall_target: float = 0.9,
) -> float:
    """Highest threshold that still meets recall_target; else best F1."""
    scores = np.asarray(scores, dtype=float)
    labels = np.asarray(labels)
    positives = labels == 1
    if not np.any(positives) or scores.size == 0:
        return 0.5

    candidates = np.unique(scores)
    best_recall_thr: float | None = None
    best_f1 = -1.0
    best_f1_thr = float(np.median(scores))

    # Highest threshold first: keep recall while maximizing precision.
    for thr in sorted(candidates, reverse=True):
        pred = scores >= thr
        tp = int(np.sum(pred & positives))
        fp = int(np.sum(pred & ~positives))
        fn = int(np.sum(~pred & positives))
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        if f1 >= best_f1:
            best_f1 = f1
            best_f1_thr = float(thr)
        if recall >= recall_target and best_recall_thr is None:
            best_recall_thr = float(thr)

    if best_recall_thr is not None:
        return best_recall_thr
    return best_f1_thr
