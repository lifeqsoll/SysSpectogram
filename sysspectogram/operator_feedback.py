"""Operator feedback: ignore / baseline / anomaly for processes.

v0.7: thin re-export of ProcessLabelStore (rules with exact/prefix/glob).
Legacy import paths keep working.
"""

from __future__ import annotations

from sysspectogram.process_labels import (  # noqa: F401
    FeedbackEntry,
    Label as Kind,
    OperatorFeedback,
    ProcessLabelRule,
    ProcessLabelStore,
    process_key,
)

__all__ = [
    "FeedbackEntry",
    "Kind",
    "OperatorFeedback",
    "ProcessLabelRule",
    "ProcessLabelStore",
    "process_key",
]
