# Operator feedback (Telegram)

Tune false positives without editing YAML by hand.

## Buttons (after `/unlock`)

| Action | Effect |
| --- | --- |
| **Ignore** / Ignore proc | Suppress matching `comm`/`path` for a while |
| **As normal** | Bias scorer toward benign for that fingerprint |
| **As anomaly** | Bias toward anomaly (and can feed retrain) |
| **Kill** | SIGKILL target PID (confirm + unlock) |

Payloads are tokenized; mutations require console unlock.

## Learner

- Runtime bias: `feedback_learn` adjusts agent/host scores from labeled events.
- Optional retrain on a **builder** PC: collect feedback → rebuild dataset window → pack.

```bash
# example — see CLI help for exact flags
python -m sysspectogram feedback-retrain --help
```

Do **not** expect full CNN retrain on a 1 GB VPS. Collect on VPS, train on PC, push artifacts ([TRAIN_BRIDGE.md](TRAIN_BRIDGE.md)).

## Safety

- Feedback never disables HMAC / kirk CRITICAL by itself.
- Prefer Ignore for noisy known daemons; As anomaly for confirmed bad paths.

See [TELEGRAM.md](TELEGRAM.md) and [ROLE_LAB.md](ROLE_LAB.md).
