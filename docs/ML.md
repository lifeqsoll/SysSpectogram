# Host ML pipeline (§5.3–5.4)

Short notes for training, promotion, and the optional agent scorer. Full offline metrics: [EVAL.md](EVAL.md).

## Runtime

- **Target default runtime:** `onnx` on the guard path after `check_ml_ready.py` passes on your data.
- Today many installs still ship with `runtime.prefer: notorch` until you promote artifacts locally.
- `export_cnn_onnx` writes `feature_schema_version` / `train_set_hash` into `meta.json` when those arguments are set, refreshes the manifest, and can minisign that manifest (`minisign_secret_key`).

## Feature event stream

Guard ticks can append `FeatureEvent` rows (schema v1) via `sysspectogram.ml.feature_events.append_feature_event` to a JSONL path (e.g. under `reports/`). Each line carries `rule_id`, `severity`, `exe`, `ppid`, fuse/host scores, and optional `extras`. Operator actions map to weak labels (`weak_label_from_decision`: ban/kill/isolate → +1, mute/fp/allow → −1, ignore → skip). Telegram ban/kill/isolate (including lockdown / kirk isolate), mute, allow, and host false-positive buttons append those events. `/status` includes `ml_phase=`.

## Shadow metrics (guard-core)

`guard_core.shadow: true` compares Python CPU/mem with the `sysspectogram-guard-core` binary about every 30s and appends the diff to `reports/guard_core_shadow.jsonl`. `guard_core.use_for_metrics: true` prefers the Rust sample for `cpu_percent` / `mem_percent` and keeps the Python values when the binary is missing or fails. The guard logs the binary path at startup when either flag is on. Auth-line and `/proc/net/tcp` helpers are on the same CLI (`auth-fail-ip`, `tcp-addr`); they do not replace the Python perimeter loop.

## Adaptive thresholds

`ml.adaptive_thresholds: true` persists per-rule hit/FP counts and an EWMA (`state/rule_thresholds.json` by default). A hot false-positive EWMA steps severity down one rank before notify. **Critical is never softened.** Mute, ignore, and host FP-suppress paths record a false positive; emitted alerts record a hit.

## Promote / shadow

`sysspectogram.ml.model_promote` copies a candidate into `ml.shadow_dir`, checks it with `supply_chain.verify_artifacts`, then rotates `ml.live_dir` aside (default sibling `ml-previous`) and moves shadow into live. `rollback` swaps them back. `read_ml_phase` / `write_ml_phase` store `off`, `shadow`, or `live` (default `state/ml_phase.json`).

## Agent ONNX (optional)

The Rust agent can link `tract-onnx` with `--features onnx` (not in the default build). `--onnx-model` plus a `<model>.sha256` sidecar loads `OnnxScorer`; `--onnx-shadow` sets `ml_shadow` on the alert. Either way the agent only adds `ml_score` extras. Rule severity stays with the agent `RuleEngine`. Without the feature or the model, scoring is a no-op.

## Still Python-owned

- Perimeter **RuleEngine**, response/ban policy, and host/agent **risk fusion** still run in Python. guard-core does not replace those loops.
- A full supervised eval beyond the mini reference gate is still a separate training task. The agent tract feature is optional and is not in the default musl binary.
