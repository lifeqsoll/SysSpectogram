# Configuration reference

[English](CONFIG.md) · [Русский](CONFIG_RU.md)

Default file: [`configs/default.yaml`](../configs/default.yaml).  
Override path with the global flag `--config /path/to.yaml`.

CLI flags override selected keys when both are present (for example `--epochs` overrides `train.epochs`).

---

## `collector`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `interval_sec` | float | `1.0` | Sleep target between samples in `collect` / monitor sampling loop |
| `max_cores` | int | `16` | Fixed number of `cpu_core_*` columns (pad/truncate host cores) |
| `socket_sample_every` | int | `5` | Refresh ESTABLISHED/LISTEN counts every N samples (cheaper than every second) |

---

## `window`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `size` | int | `60` | Rows per window (seconds if `interval_sec` is 1) |
| `stride` | int | `5` | Step between windows in `build-dataset` and `analyze` |

CLI `--window` / `--stride` on `build-dataset` override these when set.

---

## `train`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `epochs` | int | `15` | CNN epochs (overridden by `--epochs`) |
| `batch_size` | int | `32` | DataLoader batch size |
| `lr` | float | `0.001` | Adam learning rate |
| `val_ratio` | float | `0.2` | Fraction of windows held out for validation when building the dataset |
| `seed` | int | `42` | RNG seed for split and training |
| `cnn_weight` | float | `0.6` | Weight of CNN anomaly probability in fusion |
| `iforest_weight` | float | `0.4` | Weight of Isolation Forest score in fusion |
| `recall_target` | float | `0.9` | Validation recall target used to pick the decision threshold |

Fusion is renormalized so the two weights sum to 1.

---

## `monitor`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `interval_sec` | float | `5` | Seconds between inferences (CLI `--interval`) |
| `cooldown_sec` | float | `60` | Minimum seconds between alerts (CLI `--cooldown`) |
| `top_processes` | int | `3` | How many processes to list on alert |

---

## `ensemble`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `default_threshold` | float | `0.5` | Fallback only; trained `artifacts/meta.json` threshold is used at inference |

---

## `host` / `perimeter` / `recon` / `telegram`

See Russian config doc or `configs/default.yaml` for v0.2 keys (`host.id`, perimeter thresholds, denylist, auto recon, Telegram token/chat). Env: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`.

---

## Environment notes

- v0.2 adds `watch-perimeter`, `recon`, `guard` with Telegram slash + inline confirm. No auto-kill/ban without confirm.  
- Changing `max_cores` or feature schema requires rebuilding the dataset and retraining; old artifacts will not match new column layouts.
