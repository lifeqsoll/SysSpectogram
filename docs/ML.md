# Host ML pipeline

Short notes for training, promotion, optional agent scoring, and how host ML sits next to **guard-core**. Full offline metrics: [EVAL.md](EVAL.md).

## Runtime (1.5.0)

- Default **`runtime.prefer: onnx`** in `configs/default.yaml`. No torch on the guard hot path.
- Without `cnn.onnx` / a usable artifacts dir the host loop stays **metrics-only** (perimeter + agent fuse) — it does **not** hard-fail or skip timeseries.
- Prefer ONNX for production VPS. Use `torch_ml` only on builder boxes. Force with `SYSSPECTOGRAM_RUNTIME=notorch|onnx|torch_ml`.
- Trust fuse / host CNN scores only after `check_ml_ready.py` passes on **your** data ([EVAL.md](EVAL.md)).
- `export_cnn_onnx` writes `feature_schema_version` / `train_set_hash` into `meta.json` when set, refreshes the manifest, and can minisign it (`minisign_secret_key`).

## Feature event stream

Guard ticks can append `FeatureEvent` rows (schema v1) via `sysspectogram.ml.feature_events.append_feature_event` to a JSONL path (e.g. under `reports/`). Each line carries `rule_id`, `severity`, `exe`, `ppid`, fuse/host scores, and optional `extras`. Operator actions map to weak labels (`weak_label_from_decision`: ban/kill/isolate → +1, mute/fp/allow → −1, ignore → skip). Telegram ban/kill/isolate (including lockdown / kirk isolate), mute, allow, and host false-positive buttons append those events. `/status` includes `ml_phase=`.

## guard-core

`guard_core` in `configs/default.yaml`:

| Key | Default | Meaning |
| --- | --- | --- |
| `shadow` | `false` | Compare Python CPU/mem with the binary (~30s → `reports/guard_core_shadow.jsonl`) |
| `use_for_metrics` | `false` | Prefer Rust `cpu_percent` / `mem_percent` when the binary answers |
| `use_for_rules` | `true` | Live **RuleEngine** over `serve` Unix JSONL (`socket`) |
| `use_for_risk` | `true` | Live **decide_risk** over the same socket |
| `socket` | `state/guard-core.sock` | Serve path |
| `bin_sha256` | `null` | Optional pin of the binary |

If the binary or socket is missing, Python keeps the previous behaviour. CLI helpers: `metrics`, `auth-fail-ip`, `tcp-addr`, `render`, `serve`.

## Adaptive thresholds

`ml.adaptive_thresholds: true` (default) persists per-rule hit/FP counts and an EWMA (`state/rule_thresholds.json`). A hot false-positive EWMA steps severity down one rank before notify. **Critical is never softened.** Mute, ignore, and host FP-suppress paths record a false positive; emitted alerts record a hit.

## Promote / shadow

`sysspectogram.ml.model_promote` copies a candidate into `ml.shadow_dir`, checks it with `supply_chain.verify_artifacts`, then rotates `ml.live_dir` aside (default sibling `ml-previous`) and moves shadow into live. `rollback` swaps them back. `read_ml_phase` / `write_ml_phase` store `off`, `shadow`, or `live` (default `state/ml_phase.json`).

`ml.mode: one_class` is the unsupervised default; use supervised only when you have labels.

## Agent ONNX (optional)

The Rust agent can link `tract-onnx` with `--features onnx` (not in the default musl release binary). `--onnx-model` plus a `<model>.sha256` sidecar loads `OnnxScorer`; `--onnx-shadow` sets `ml_shadow` on the alert. Either way the agent only adds `ml_score` extras. Rule severity stays with the agent rules. Without the feature or the model, scoring is a no-op.

## Still Python-owned

- Response / ban policy, Telegram plane, and the host sample loop orchestration stay in Python (with optional guard-core offload for rules/risk/metrics).
- A full supervised eval beyond the mini reference gate is still a separate training task.
