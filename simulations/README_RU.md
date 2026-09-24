# Симуляции аномалий

[English](README.md) · [Русский](README_RU.md)

Отдельные генераторы нагрузки для разметки класса «аномалия». Работают **только на этой машине** (сеть — localhost). Не направляйте их на чужие хосты.

## Как пользоваться

Терминал A — сбор метрик:

```bash
python -m sysspectogram collect --out data/anomaly.csv --duration 1200
```

Терминал B — генератор:

```bash
python simulations/cpu_miner.py --duration 900
python simulations/net_flood_local.py --duration 900 --rate 100
python simulations/mem_pressure.py --duration 300 --mb 512
python simulations/disk_thrash.py --duration 300
```

Или `./simulations/run_all.sh`.

Норму собирайте отдельно в `data/normal.csv`.

Эквивалент через CLI:

```bash
python -m sysspectogram simulate cpu|mem|disk|net ...
```

## Флаги скриптов

### `cpu_miner.py`

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `--duration` | 900 | Секунды CPU burn |
| `--workers` | auto | Число процессов |

### `mem_pressure.py`

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `--duration` | 300 | Секунды |
| `--mb` | 512 | МБ выделяемой памяти |

### `disk_thrash.py`

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `--duration` | 300 | Секунды |
| `--block-mb` | 32 | Размер блока R/W |
| `--path` | `/tmp/sysspectogram_disk_thrash.bin` | Временный файл |

### `net_flood_local.py`

| Флаг | По умолчанию | Описание |
| --- | --- | --- |
| `--duration` | 900 | Секунды |
| `--rate` | 80 | TCP-коннектов/сек на `127.0.0.1` |

### `run_all.sh`

Переменные окружения: `DURATION_CPU`, `DURATION_NET`, `DURATION_MEM`, `DURATION_DISK`.

## Безопасность

Только локальные ресурсы и `127.0.0.1`. Без удалённого сканирования.

## Intrusion lab (`simulations/intrusion/`)

Сценарии периметра. Не атакуют чужие хосты. Внешний TEST-NET beacon только с `--lab`.

```bash
python simulations/intrusion/ssh_bruteforce_local.py --count 12 --out /tmp/fake_auth.log
python simulations/intrusion/port_scan_local.py --count 40
python simulations/intrusion/egress_beacon.py --local-sink --duration 8
python simulations/intrusion/lab_runner.py --lab egress_beacon
```

Параллельно: `python -m sysspectogram watch-perimeter --duration 30` или `guard`.
