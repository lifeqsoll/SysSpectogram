# SysSpectogram

[English](README.md) · [Русский](README_RU.md)

Linux-утилита для **поведенческого обнаружения аномалий на хосте** и небольшого defensive-аудита.

Раз в секунду снимает метрики ОС, режет их на окна по 60 секунд, обучает лёгкий ансамбль CNN + Isolation Forest и умеет работать в realtime или разбирать CSV офлайн. Дополнительно даёт снимок процессов и портов.

**Область (v0.2):** хосты и серверы Linux. Host ML (v1) + perimeter/egress/NIDS-lite + auto OSINT/nmap + Telegram-пульт. Это не антивирус и не полный NIDS/SIEM.

**Связанные документы:** [Конфиг](docs/CONFIG_RU.md) · [Рецепты](docs/RECIPES_RU.md) · [Telegram](docs/TELEGRAM_RU.md) · [Симуляции](simulations/README_RU.md)

---

## Содержание

1. [Что делает](#что-делает)
2. [Требования](#требования)
3. [Установка](#установка)
4. [Основные понятия](#основные-понятия)
5. [Полный цикл работы](#полный-цикл-работы)
6. [Сценарии](#сценарии)
7. [Справочник CLI](#справочник-cli)
8. [Telegram](#telegram)
9. [Артефакты и выходные файлы](#артефакты-и-выходные-файлы)
10. [Docker](#docker)
11. [systemd](#systemd)
12. [Ограничения](#ограничения-и-безопасность)
13. [Проблемы](#типичные-проблемы)

---

## Что делает

| Этап | Назначение |
| --- | --- |
| `collect` | Пишет поминутные (посекундные) rates метрик в CSV |
| `simulate` / `simulations/` | Локальная нагрузка cpu/mem/disk/net/gpu |
| `build-dataset` | Нарезает CSV на окна 60×N (train/val) |
| `train` | Обучает CNN + Isolation Forest, сохраняет артефакты |
| `monitor` | Живой детект по буферу последних 60 секунд |
| `watch-perimeter` | Auth brute / inbound scan / egress denylist / DNS |
| `recon` | OSINT + optional nmap по IP |
| `guard` | perimeter + host ML + Telegram slash/inline |
| `lab-nmap` | nmap только allowlisted lab targets |
| `analyze` | Офлайн-прогон CSV обученной моделью |
| `audit` | processes / ports / rootkit / report |

Формула скора по умолчанию:

`score = 0.6 * P_cnn(anomaly) + 0.4 * IsolationForest_score`

Порог на валидации подбирается с упором на высокий Recall (см. `configs/default.yaml`).

---

## Требования

- Linux (любой распространённый дистрибутив)
- Python 3.10+
- Опционально: `notify-send` для desktop-уведомлений
- Опционально: Docker для воспроизводимого обучения
- `stress-ng` не обязателен: встроенных симуляторов достаточно

---

## Установка

```bash
git clone <repo-url> SysSpectogram
cd SysSpectogram
python -m venv .venv
source .venv/bin/activate

# CPU-сборка PyTorch (рекомендуется без NVIDIA CUDA):
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev]"

python -m sysspectogram --help
```

После установки доступны команда `sysspectogram` и `python -m sysspectogram`.

---

## Основные понятия

### Метрики (rates, не сырые счётчики)

Каждая строка CSV — одна секунда. Сеть, диск, context switches — это **дельты в секунду**. Абсолютные счётчики в обучение не идут, чтобы uptime не доминировал над аномалией.

В колонках: CPU (общий и до `max_cores` ядер), память/swap, page faults, сетевые байты/пакеты в секунду, число сокетов ESTABLISHED/LISTEN (опрос раз в N секунд), дисковый I/O.

### Окна

- Окно по умолчанию: **60 секунд** × N признаков  
- Шаг при сборке датасета: **5 секунд** (перекрывающиеся окна)  
- `MinMax`-скейлер учится **только на train** и сохраняется для inference  

### Ансамбль

- **CNN** — маленькая сеть по одноканальному тензору 60×N  
- **Isolation Forest** — статистики по тому же окну (mean/std/max/p95)  
- Артефакты в одной папке: `cnn.pt`, `iforest.joblib`, `scaler.joblib`, `meta.json`  

### Разметка

Нужны отдельные CSV **normal** и **anomaly**. Инструмент сам разметку не придумывает. Норму собирайте в обычной работе; аномалию — через `simulate` / `simulations/` или реальные инциденты.

---

## Полный цикл работы

### 1. Нормальный профиль

```bash
python -m sysspectogram collect --out data/normal.csv --duration 3600
```

Для устойчивого профиля лучше 1–2 часа обычной нагрузки.

### 2. Аномальный профиль

Терминал A:

```bash
python -m sysspectogram collect --out data/anomaly.csv --duration 1200
```

Терминал B:

```bash
python -m sysspectogram simulate cpu --duration 900 --workers 2
# или:
python simulations/cpu_miner.py --duration 900
```

Память, диск и localhost-сеть: [simulations/README.md](simulations/README.md).

### 3. Датасет

```bash
python -m sysspectogram build-dataset \
  --normal data/normal.csv \
  --anomaly data/anomaly.csv \
  --out dataset/ \
  --window 60 \
  --stride 5
```

Флаг `--png` пишет превью; обучение идёт по `.npy`.

### 4. Обучение

```bash
python -m sysspectogram train --dataset dataset/ --out artifacts/ --epochs 15
```

Смотрите Precision / Recall / F1 и `artifacts/meta.json`.

### 5. Realtime

```bash
python -m sysspectogram monitor --model artifacts/ --interval 5 --cooldown 60
```

При аномалии: вывод в терминал, опционально `notify-send`, top-процессы, опционально JSONL.

### 6. Офлайн на сервере

```bash
python -m sysspectogram analyze \
  --csv data/night.csv \
  --model artifacts/ \
  --out reports/night.json
```

### 7. Аудит без модели

```bash
python -m sysspectogram audit processes
python -m sysspectogram audit ports
python -m sysspectogram audit report --out reports/audit.json
```

---

## Сценарии

### Домашняя/рабочая станция и имитация майнера по CPU

1. Час `collect` нормы.  
2. `collect` аномалии параллельно с `simulate cpu`.  
3. `build-dataset` → `train` → `monitor`.  

**Зачем:** ловить устойчивые аномальные паттерны CPU и сразу видеть PID в топе.

### VPS: ночной лог без интерактива

1. Таймер: `collect --duration 86400`.  
2. Утром: `analyze` по CSV с готовыми `artifacts/`.  

**Зачем:** ретроспектива поведения без постоянного GUI-сеанса.

### Быстрый разбор «что сейчас на хосте»

```bash
python -m sysspectogram audit report --out reports/triage.json
```

**Зачем:** инвентаризация нагрузки и портов. Дополняет `monitor`, не заменяет его.

### Смена роли сервера

После смены сервисов соберите новый normal CSV и переобучите модель. Старые артефакты описывают старую «норму».

---

## Справочник CLI

Общий вид:

```text
python -m sysspectogram [--config PATH] [--version] <command> ...
```

| Глобальный флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--config` | нет | `configs/default.yaml` | YAML с настройками collector/window/train/monitor |
| `--version` | нет | — | Версия пакета |
| `-h` / `--help` | нет | — | Справка по программе или подкоманде |

---

### `collect`

Пишет метрики в CSV (дописывает; заголовок — если файл новый/пустой).

```bash
python -m sysspectogram collect --out data/normal.csv --duration 3600
```

| Флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--out` | **да** | — | Путь к CSV |
| `--duration` | нет | бесконечно (до Ctrl+C) | Останов через N секунд |

Из конфига: `collector.interval_sec`, `max_cores`, `socket_sample_every`.

---

### `build-dataset`

Нарезка CSV в `train/` и `val/` как `.npy`.

```bash
python -m sysspectogram build-dataset \
  --normal data/normal.csv \
  --anomaly data/anomaly.csv \
  --out dataset/ \
  --window 60 \
  --stride 5 \
  --png
```

| Флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--normal` | **да** | — | Один или несколько CSV нормы |
| `--anomaly` | **да** | — | Один или несколько CSV аномалии |
| `--out` | **да** | — | Корень датасета |
| `--window` | нет | `window.size` (60) | Число строк в окне |
| `--stride` | нет | `window.stride` (5) | Шаг между окнами |
| `--png` | нет | выкл. | Дополнительно PNG-превью |

Создаёт `meta.json` и `scaler.joblib` в корне датасета.

---

### `train`

Обучение ансамбля.

```bash
python -m sysspectogram train --dataset dataset/ --out artifacts/ --epochs 15
```

| Флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--dataset` | **да** | — | Корень датасета |
| `--out` | **да** | — | Каталог артефактов |
| `--epochs` | нет | `train.epochs` (15) | Эпохи CNN |

Остальные гиперпараметры — из YAML (`batch_size`, `lr`, веса fusion, `recall_target`, `seed`).

---

### `monitor`

Realtime: раз в 1 с сэмпл в deque на `window_size`, inference каждые `--interval` секунд.

```bash
python -m sysspectogram monitor \
  --model artifacts/ \
  --interval 5 \
  --cooldown 60 \
  --jsonl-out reports/alerts.jsonl
```

| Флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--model` | **да** | — | Каталог артефактов |
| `--interval` | нет | `monitor.interval_sec` (5) | Пауза между inference |
| `--cooldown` | нет | `monitor.cooldown_sec` (60) | Мин. пауза между алертами |
| `--jsonl-out` | нет | нет | JSONL с событиями аномалий |

Останов: Ctrl+C.

---

### `analyze`

Скользящие окна по CSV.

```bash
python -m sysspectogram analyze \
  --csv data/anomaly.csv \
  --model artifacts/ \
  --out reports/analyze.json
```

| Флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `--csv` | **да** | — | Входной CSV |
| `--model` | **да** | — | Артефакты |
| `--out` | нет | нет | JSON-отчёт (сводка печатается всегда) |

Шаг окон — `window.stride` из конфига.

---

### `audit`

Снимок хоста. Позиционный аргумент выбирает режим.

```bash
python -m sysspectogram audit processes
python -m sysspectogram audit ports
python -m sysspectogram audit report --out reports/audit.json
```

| Аргумент / флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `what` | **да** | — | `processes` \| `ports` \| `report` |
| `--out` | нет | stdout для `report` | Путь JSON при `report` |

---

### `simulate`

Локальные генераторы нагрузки. Сеть — только `127.0.0.1`.

```bash
python -m sysspectogram simulate cpu --duration 900 --workers 2
python -m sysspectogram simulate mem --duration 300 --mb 512
python -m sysspectogram simulate disk --duration 300 --block-mb 32
python -m sysspectogram simulate net --duration 900 --rate 80
python -m sysspectogram simulate gpu --duration 60 --gpu-size 4096
```

| Аргумент / флаг | Обязателен | По умолчанию | Описание |
| --- | --- | --- | --- |
| `kind` | **да** | — | `cpu` \| `mem` \| `disk` \| `net` \| `gpu` |
| `--duration` | нет | 60 | Длительность, сек |
| `--workers` | нет | ~половина CPU | Число процессов для `cpu` |
| `--mb` | нет | 512 | МБ памяти для `mem` |
| `--block-mb` | нет | 32 | Размер блока для `disk` |
| `--rate` | нет | 80 | Коннектов/сек на localhost для `net` |
| `--gpu-size` | нет | 2048 | Размер матрицы для `gpu` (нужен CUDA torch) |

Скрипты в `simulations/` делают то же самое вне CLI.

### Лучшие рецепты

Полный набор: **[docs/RECIPES_RU.md](docs/RECIPES_RU.md)**.

```bash
python -m sysspectogram collect --out data/normal.csv --duration 1800
python -m sysspectogram simulate cpu --duration 900 --workers 8 &
python -m sysspectogram collect --out data/anomaly_cpu.csv --duration 900
python -m sysspectogram build-dataset \
  --normal data/normal.csv --anomaly data/anomaly_cpu.csv \
  --out dataset/real --window 60 --stride 5 \
  --max-normal-cpu-mean 25 --min-anomaly-cpu-mean 45
python -m sysspectogram train --dataset dataset/real --out artifacts/real_v3 --epochs 25
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

---

### `watch-perimeter`

Auth journal + inbound/egress + DNS watch. Auto recon на alert (cooldown per IP).

```bash
python -m sysspectogram watch-perimeter --duration 60 --jsonl-out reports/perimeter.jsonl
```

### `recon`

```bash
python -m sysspectogram recon 203.0.113.50
python -m sysspectogram recon 203.0.113.50 --no-nmap
```

### `guard`

Периметр + host ML + Telegram (нужны `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` в `.env`).

```bash
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

---

## Telegram

Полный справочник: **[docs/TELEGRAM_RU.md](docs/TELEGRAM_RU.md)** · рецепты: **[docs/RECIPES_RU.md](docs/RECIPES_RU.md)**.

С телефона (пока крутится `guard --telegram`): `/help` `/menu` `/panel` `/score` `/audit` `/processes` `/ports` `/rootkit` `/simulate` `/collect` `/analyze` `/recon` `/ban` `/recipes` …

Длинные `train` / `build-dataset` / `monitor` — только в терминале. На алерте — dual heatmap + confirm Ban/Kill.

### `lab-nmap`

```bash
python -m sysspectogram lab-nmap 127.0.0.1 --lab
```

### `audit`

```bash
python -m sysspectogram audit processes
python -m sysspectogram audit ports
python -m sysspectogram audit rootkit
python -m sysspectogram audit report --out reports/audit.json
```

---

## Артефакты и выходные файлы

| Путь | Содержимое |
| --- | --- |
| `data/*.csv` | Временной ряд метрик |
| `dataset/train|val/.../*.npy` | Окна |
| `dataset/scaler.joblib` | Скейлер |
| `dataset/meta.json` | Колонки, окно, counts |
| `artifacts/*` | Модель, порог, метрики |
| `reports/*.json` | Отчёты analyze/audit |
| `reports/*.jsonl` | Поток алертов monitor |

---

## Docker

**Внимание:** Docker удобен для **train** / **analyze**. Не запускайте `monitor` / `guard` в обычном контейнере ожидая IDS «как на хосте» — видны cgroup-метрики и сетевой namespace контейнера. `--pid=host --net=host` — осознанный компромисс. Для live-детекции предпочтительна native systemd-установка.

```bash
docker build -t sysspectogram .
docker run --rm \
  -v "$PWD/dataset:/dataset" \
  -v "$PWD/artifacts:/artifacts" \
  sysspectogram train --dataset /dataset --out /artifacts
```

В образе по умолчанию CPU PyTorch.

---

## systemd

- Monitor: [scripts/systemd/sysspectogram-monitor.service](scripts/systemd/sysspectogram-monitor.service)
- Guard: [scripts/systemd/sysspectogram-guard.service](scripts/systemd/sysspectogram-guard.service)

Секреты — в `/opt/sysspectogram/.env` (или `/etc/sysspectogram.env`); unit'ы читают `EnvironmentFile=-…`. Укажите `--model`, затем `systemctl enable --now …`. В unit'ах есть hardening (`ProtectSystem`, `PrivateTmp`, …); для живого nft без `--dry-run` может понадобиться ослабить ограничения.

---

## Ограничения и безопасность

- Качество модели = качество **ваших** размеченных CSV. Модель с ноутбука не равна профилю БД на VPS.  
- Не ловит kernel-rootkit и не знает malware по имени.  
- Симуляции только на этой машине / localhost.  
- Эвристики `audit` — подсказки, не доказательство.  
- Без notification daemon уведомления только в терминал/JSONL.  

---

## Типичные проблемы

| Симптом | Что проверить |
| --- | --- |
| Нет окон в `build-dataset` | CSV короче `--window` |
| Плохой F1 | Мало данных, пересекающиеся классы, дисбаланс |
| `monitor` молчит | Порог; проверьте `analyze` на заведомой аномалии |
| Спам алертов | Увеличьте `--cooldown` |
| Ошибки torch | Переустановите CPU wheel с официального CPU index |
| Пустые сокеты | Права / нет `/proc/net/tcp` в окружении |

```bash
pytest -q
```

---

## Лицензия

MIT. См. [LICENSE](LICENSE).

## О следующих версиях

Perimeter/Telegram/OSINT уже в v0.2 — см. [TELEGRAM_RU.md](docs/TELEGRAM_RU.md) и [RECIPES_RU.md](docs/RECIPES_RU.md).
