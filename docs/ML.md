# Host ML pipeline (§5.3–5.4 prep)

Short notes for the next training/eval iteration. Full offline metrics: [EVAL.md](EVAL.md).

## Runtime

- **Target default runtime:** `onnx` on the guard path after `check_ml_ready.py` passes on your data.
- Today many installs still ship with `runtime.prefer: notorch` until you promote artifacts locally.

## Feature event stream

Guard ticks can append `FeatureEvent` rows (schema v1) via `sysspectogram.ml.feature_events.append_feature_event` to a JSONL path (e.g. under `reports/`). Each line carries `rule_id`, `severity`, `exe`, `ppid`, fuse/host scores, and optional `extras`. Operator actions map to weak labels (`weak_label_from_decision`: ban/kill/isolate → +1, mute/fp/allow → −1, ignore → skip).

## Shadow mode (planned)

ML scores will eventually run in **shadow** alongside rule decisions: log and compare without changing ban/kill policy until metrics and operator review justify promotion.

## Known (1.6)

- **tract-in-agent:** ONNX/Torch inference remains on the Python guard; moving a tract runtime into the Rust agent is deferred.
- **guard-core migration:** Perimeter enforcement and scoring continue to straddle Python and `guard-core`; a full cutover is tracked for 1.6.