# ADR 0001: fusion gating and agent score decay

Status: accepted for v1.0 (implementation: Phase 0).

## Context

`fuse_host_agent` computes `0.6 * host + 0.4 * agent`. The guard compares the result with `ensemble.risk_threshold: 0.7`. The agent score starts at 0 and never decays once set. With a quiet agent the maximum fused risk is 0.6, so host-only anomalies can never reach the threshold.

## Decision

- Keep the fused formula.
- Change the gate: an anomaly fires when `host >= host.threshold` **or** `fused >= ensemble.risk_threshold`.
- Decay the agent score: `ascore * exp(-age / agent.score_half_life_sec)`, default 60 s.
- Align training weights with the documented formula (`train.cnn_weight: 0.6`, `iforest_weight: 0.4`). Existing artifacts keep their weights, which are stored in `meta.json`.

## Consequences

- Host-only anomalies alert again. Expect more alerts on noisy hosts; the replay in the test block measures FP and FN before and after.
- Agent alerts no longer stick forever.

## Alternatives rejected

- Lower `risk_threshold` to 0.5: makes the agent weight meaningless and raises FP.
- Use `max(host, agent)`: loses the combined signal.
