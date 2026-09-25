# Справочник конфигурации

[English](CONFIG.md) · [Русский](CONFIG_RU.md)

Файл по умолчанию: [`configs/default.yaml`](../configs/default.yaml).  
Путь можно задать глобальным флагом `--config /path/to.yaml`.

Флаги CLI имеют приоритет над отдельными ключами (например `--epochs` перекрывает `train.epochs`).

---

## `collector`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `interval_sec` | float | `1.0` | Целевой интервал между сэмплами |
| `max_cores` | int | `16` | Фиксированное число колонок `cpu_core_*` |
| `socket_sample_every` | int | `5` | Обновление ESTABLISHED/LISTEN раз в N сэмплов |

---

## `window`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `size` | int | `60` | Строк в окне |
| `stride` | int | `5` | Шаг окон в `build-dataset` и `analyze` |

CLI `--window` / `--stride` у `build-dataset` перекрывают эти значения.

---

## `train`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `epochs` | int | `15` | Эпохи CNN (`--epochs`) |
| `batch_size` | int | `32` | Размер батча |
| `lr` | float | `0.001` | Learning rate Adam |
| `val_ratio` | float | `0.2` | Доля окон в validation при сборке датасета |
| `seed` | int | `42` | Seed |
| `cnn_weight` | float | `0.6` | Вес CNN в fusion |
| `iforest_weight` | float | `0.4` | Вес Isolation Forest в fusion |
| `recall_target` | float | `0.9` | Целевой Recall для выбора порога |

Веса fusion нормализуются к сумме 1.

---

## `monitor`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `interval_sec` | float | `5` | Пауза между inference (`--interval`) |
| `cooldown_sec` | float | `60` | Пауза между алертами (`--cooldown`) |
| `top_processes` | int | `3` | Сколько процессов показывать в алерте |

---

## `ensemble`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `default_threshold` | float | `0.5` | Запасной порог; на inference берётся `artifacts/meta.json` |

---

## `host`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `id` | str/null | hostname | Префикс во всех Telegram-сообщениях |

## `perimeter`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `poll_sec` | float | `2` | Интервал опроса auth/conn/DNS |
| `fail_threshold` | int | `8` | SSH fails для brute |
| `fail_window_sec` | float | `60` | Окно brute |
| `scan_unique_ips` | int | `8` | Уникальных IP на порт → scan |
| `denylist_paths` | list | `configs/denylist.txt` | Egress denylist |
| `suspicious_domains` | list | … | DNS NIDS-lite |
| `state_path` | path | `state/perimeter.json` | allowlist/mute/quiet |
| `jsonl_out` | path | `reports/perimeter.jsonl` | JSONL алертов |

## `recon`

| Ключ | Тип | По умолчанию | Смысл |
| --- | --- | --- | --- |
| `auto` | bool | `true` | Auto OSINT+nmap на alert |
| `nmap` | bool | `true` | `nmap -F` (soft-fail) |
| `cooldown_sec` | float | `900` | Cooldown per IP |
| `passive_dns_url` | str/null | null | Шаблон URL с `{ip}` |

## `telegram`

Токен/chat можно задать в YAML или через `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`.

| Ключ | Смысл |
| --- | --- |
| `bot_token` | Bot API token |
| `chat_id` | Allowlisted chat |
| `token_secret` | HMAC secret для inline callback tokens |
| `require_console_unlock` | `true` — после старта TG/web actions LOCKED до `/unlock` |
| `unlock_ttl_sec` | TTL сессии unlock (по умолчанию `7200` = 2ч) |

## `agent` (v0.4)

| Ключ | Смысл |
| --- | --- |
| `enabled` | Слушать Unix-сокет агента в `guard` |
| `auto_start` | Спавнить `sysspectogram-agent` |
| `mode` | `userspace` (default) / `ebpf` (clang BPF + Aya; attach нужен **root**) |
| `metrics` | Лёгкие метрики на live web |
| `socket` | `null` → `$XDG_RUNTIME_DIR/sysspectogram-agent.sock` (0600) |
| `cooldown_sec` | Cooldown TG-алертов агента |

---

## Замечания

- v0.4: fuse risk, packs, lite/full, FIM/flow в `full`, опциональный eBPF. Console unlock гейтит TG/web kill/ban.  
- Смена `max_cores` или схемы признаков требует нового датасета и переобучения.
