# ADR 0002: event spectrogram from agent alerts

Status: accepted for v1.0 (Phase 1). The CNN part ships only if it beats the IF baseline.

## Context

The Rust agent emits discrete alerts. Turning them into a time by event-type matrix gives a spectrogram-like input. Host metrics from Rust (`cpu`, `mem`, `net`) duplicate the Python collector and do not cover the trained columns.

## Decision

1. Stage 1a: `AgentEventMatrix` builds 1 Hz buckets per rule group. Features are mean and max per channel and feed the Isolation Forest through `train_agent_iforest`.
2. Stage 1b: a 60 x K single-channel CNN over the same buckets, exported to `agent_spectro.onnx`, behind `agent.spectrogram: false`.
3. Rust metrics are not added to the host CNN.

## Consequences

- Attribution per rule group is kept.
- Labelled data comes from `simulations/intrusion/lab_runner.py`. Splits are by session to avoid leakage.
- Event poisoning is limited by per-channel caps.
