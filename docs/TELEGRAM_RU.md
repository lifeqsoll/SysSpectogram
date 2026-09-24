# Telegram — пульт управления

[English](TELEGRAM.md) · [Русский](TELEGRAM_RU.md)

`guard --telegram` даёт управление с телефона: статус, аудит, OSINT, симуляции и действия с confirm. Принимается только `TELEGRAM_CHAT_ID`.

## Настройка

```bash
# .env (не в git)
TELEGRAM_BOT_TOKEN=123:ABC
TELEGRAM_CHAT_ID=6360...

python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

`--dry-run`: ban/kill/shield только текстом, без nft/SIGKILL.

## Slash-команды

### Статус
`/ping` `/help` `/start` `/menu` `/version` `/status` `/digest` `/last [n]` `/recipes`

### Аудит хоста (= CLI `audit`)
| Команда | Смысл |
| --- | --- |
| `/audit` | сводный отчёт |
| `/processes` | топ процессов |
| `/ports` | listen/established |
| `/rootkit` | эвристики |
| `/panel` | живая спектрограмма (метрики + top-PID CPU) |
| `/score` | окно ~65с + score модели + панель |

### Периметр / ответ
`/recon` `/labnmap` `/ban` `/unban` `/kill` `/allow` `/mute` `/quiet` `/lockdown` `/bans` `/report`

### Нагрузка / сбор / analyze
`/simulate cpu|mem|disk|net|gpu [сек]` — confirm, max 120с  
`/collect [сек]` — max 180с → `reports/tg_collect.csv`  
`/analyze <csv>` — нужен `--model` у guard

### Только в терминале
`train` / `build-dataset` / `monitor` / `guard` / `watch-perimeter` — см. `/recipes`.

## Inline на алерте

Ban / Allowlist / Mute / Recon / Shield / Kill / Ignore / Report / Lockdown.  
Разрушительное — только после YES/NO (HMAC-токен, одноразовый).

## Безопасность

Только allowlisted chat · нет shell с телефона · нет авто-ban/kill · симы только локально.

## См. также

[Рецепты CLI](RECIPES_RU.md) · [Config](CONFIG_RU.md)
