# Best command recipes

[English](RECIPES.md) · [Русский](RECIPES_RU.md)

Copy-paste oriented. Prefer `python -m sysspectogram` from a venv with `.env` loaded for Telegram.

## A. First-time train (recommended)

```bash
# quiet baseline ~30m
python -m sysspectogram collect --out data/normal.csv --duration 1800

# anomaly (CPU) — other terminal
python -m sysspectogram simulate cpu --duration 900 --workers 8
# while that runs:
python -m sysspectogram collect --out data/anomaly_cpu.csv --duration 900

python -m sysspectogram build-dataset \
  --normal data/normal.csv \
  --anomaly data/anomaly_cpu.csv \
  --out dataset/real \
  --window 60 --stride 5 --png \
  --max-normal-cpu-mean 25 --min-anomaly-cpu-mean 45

python -m sysspectogram train --dataset dataset/real --out artifacts/real_v3 --epochs 25
```

**Why these flags:** filter overlapping windows so normal stays low-CPU and anomalies stay hot; improves F1 vs raw CSVs.

## B. Multi-signal anomalies (optional)

```bash
python -m sysspectogram simulate net --duration 600 --rate 120 &
python -m sysspectogram collect --out data/anomaly_net.csv --duration 600

python -m sysspectogram simulate mem --duration 300 --mb 8192 &
python -m sysspectogram collect --out data/anomaly_mem.csv --duration 300

python -m sysspectogram build-dataset \
  --normal data/normal.csv \
  --anomaly data/anomaly_cpu.csv data/anomaly_net.csv \
  --out dataset/real_mix --window 60 --stride 5
```

## C. Production-ish guard

```bash
# safe first
python -m sysspectogram guard --model artifacts/real_v3 \
  --telegram --dry-run --jsonl-out reports/guard.jsonl

# then real response actions (still needs TG confirm for ban/kill)
python -m sysspectogram guard --model artifacts/real_v3 \
  --telegram --jsonl-out /var/log/sysspectogram-guard.jsonl
```

## D. Perimeter-only / OSINT

```bash
python -m sysspectogram watch-perimeter --jsonl-out reports/perimeter.jsonl
python -m sysspectogram recon 198.51.100.20
python -m sysspectogram lab-nmap 127.0.0.1 --lab
```

## E. Offline & audit

```bash
python -m sysspectogram analyze \
  --csv data/anomaly_cpu.csv --model artifacts/real_v3 \
  --out reports/analyze.json

python -m sysspectogram audit report --out reports/audit.json
python -m sysspectogram audit rootkit
python -m sysspectogram audit processes
python -m sysspectogram audit ports
```

## F. Load generators

```bash
python -m sysspectogram simulate cpu --duration 120 --workers 8
python -m sysspectogram simulate mem --duration 90 --mb 8192
python -m sysspectogram simulate disk --duration 60 --block-mb 32
python -m sysspectogram simulate net --duration 60 --rate 120
python -m sysspectogram simulate gpu --duration 60 --gpu-size 4096   # needs CUDA torch
# or scripts: simulations/cpu_miner.py, simulations/intrusion/lab_runner.py --lab ...
```

## G. Telegram phone workflow

1. Start `guard --telegram --dry-run --model ...`
2. `/panel` — readable dual heatmap  
3. `/score` — one-shot model check  
4. `/simulate cpu 40` → YES — force host alert  
5. On alert: Ban is dry-run until you drop `--dry-run`  
6. `/recon <ip>` / `/audit` / `/recipes`

## H. systemd

```bash
# edit paths + Environment=TELEGRAM_* in:
# scripts/systemd/sysspectogram-guard.service
sudo systemctl enable --now sysspectogram-guard.service
```
