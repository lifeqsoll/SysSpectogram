# Лучшие комбинации команд

[English](RECIPES.md) · [Русский](RECIPES_RU.md)

Готовые рецепты. Telegram: см. также [TELEGRAM_RU.md](TELEGRAM_RU.md).

## A. Первое обучение (рекомендуется)

```bash
python -m sysspectogram collect --out data/normal.csv --duration 1800

python -m sysspectogram simulate cpu --duration 900 --workers 8
python -m sysspectogram collect --out data/anomaly_cpu.csv --duration 900

python -m sysspectogram build-dataset \
  --normal data/normal.csv \
  --anomaly data/anomaly_cpu.csv \
  --out dataset/real \
  --window 60 --stride 5 --png \
  --max-normal-cpu-mean 25 --min-anomaly-cpu-mean 45

python -m sysspectogram train --dataset dataset/real --out artifacts/real_v3 --epochs 25
```

Фильтры CPU на `build-dataset` сильно улучшают F1 при «грязной» норме.

## B. Guard + Telegram

```bash
python -m sysspectogram guard --model artifacts/real_v3 \
  --telegram --dry-run --jsonl-out reports/guard.jsonl

# потом без --dry-run (ban/kill всё равно только после YES в TG)
python -m sysspectogram guard --model artifacts/real_v3 --telegram
```

## C. Периметр / OSINT

```bash
python -m sysspectogram watch-perimeter --jsonl-out reports/perimeter.jsonl
python -m sysspectogram recon 198.51.100.20
python -m sysspectogram lab-nmap 127.0.0.1 --lab
```

## D. Analyze / audit

```bash
python -m sysspectogram analyze --csv data/anomaly_cpu.csv \
  --model artifacts/real_v3 --out reports/analyze.json
python -m sysspectogram audit report --out reports/audit.json
python -m sysspectogram audit rootkit
```

## E. Симуляции

```bash
python -m sysspectogram simulate cpu --duration 120 --workers 8
python -m sysspectogram simulate mem --duration 90 --mb 8192
python -m sysspectogram simulate net --duration 60 --rate 120
python -m sysspectogram simulate gpu --duration 60 --gpu-size 4096
```

## F. С телефона

1. `guard --telegram --dry-run --model ...`  
2. `/panel` → `/score` → `/simulate cpu 40` → YES  
3. На алерте смотри dual heatmap + Kill/Ban  
4. `/recon` `/audit` `/recipes`
