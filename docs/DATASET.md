# Dataset card (host ML)

SysSpectogram does **not** ship full production captures in-repo (privacy). Use local collects + [EVAL.md](EVAL.md).

## Schema

| Field | Meaning |
| --- | --- |
| `windows_format` | must be `raw` (schema v2) |
| `train` / `val` / `test` | time-ordered; gap ≥ `window_size` rows between adjacent splits |
| `labels` | window folders `normal/` / `anomaly/` (optional future: `labels.csv` from `scripts/collect_labeled.py`) |

## Lab filters

`--lab-filters` (or explicit CPU/mem/pkt thresholds) can make classes separable **by construction**. Leave **off** for honest eval. Record in `meta.json` → `filters.lab_filters`.

## Sample

Optional tiny anonymized fixtures live under `tests/fixtures/` when added for CI `ml-eval`. Do not commit real host logs or Telegram tokens.

## Known biases

- Lab CSV with high-CPU “anomaly” scenarios ≠ quiet VPS + slow APT.
- Historical raw_v4 numbers (see EVAL.md history) used lab-friendly filters — do not cite as production accuracy.
