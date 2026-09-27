# Operator feedback (Telegram) — v0.7

Tune false positives without editing YAML by hand — **on the VPS**, without CNN fine-tune.

## Buttons (after `/unlock`)

| Action | Effect |
| --- | --- |
| **Ignore** / Ignore proc | Suppress matching process (label `ignore`) |
| **As normal** | `ProcessLabelRule` baseline (+ optional widen) + threshold bias |
| **As anomaly** | Rule anomaly + bias (and can feed IF / builder retrain) |
| **+ similar** | Add `comm_prefix` / path glob widen rules |
| **Kill** | SIGKILL target PID (confirm + unlock) |

## ProcessLabelRules (primary on VPS)

Persisted in `state/process_labels.json` (schema v2). Match kinds:

- `exact`, `comm_prefix`, `comm_regex`, `path_glob`, `path_contains`, `cmdline_contains`

Priority: **anomaly > ignore > baseline**.

```bash
python -m sysspectogram labels list
python -m sysspectogram labels seed --role ssh
python -m sysspectogram labels del <id>
```

TG: `/labels`, `/label-del <id|pattern>`.

Legacy `state/operator_feedback.json` migrates on first load.

## Threshold bias

`FeedbackLearner` still nudges global risk threshold (±0.02 / −0.03) and may save host window `.npy`.

## IsolationForest refit (optional, VPS-safe)

CNN / ONNX stay frozen. Opt-in:

```yaml
feedback:
  if_refit: true
  widen_rules: comm_prefix
```

```bash
python -m sysspectogram feedback retrain-if --model artifacts/real_v3
```

Debounced after enough baseline+anomaly samples when enabled in guard.

## Full CNN retrain (builder PC)

Do **not** expect full CNN retrain on a 1 GB VPS.

```bash
python -m sysspectogram feedback retrain --feedback-dir artifacts/feedback --out artifacts/from_feedback
```

Then push artifacts ([TRAIN_BRIDGE.md](TRAIN_BRIDGE.md)).

## Safety

- Feedback never disables HMAC / kirk CRITICAL by itself.
- Prefer Ignore for noisy known daemons; As anomaly for confirmed bad paths.
- Actions append to `reports/response_audit.jsonl`.

See [TELEGRAM.md](TELEGRAM.md), [CONFIGURE.md](CONFIGURE.md), [ROLE_LAB.md](ROLE_LAB.md).
