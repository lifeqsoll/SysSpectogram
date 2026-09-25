# Telegram — пульт управления

[English](TELEGRAM.md) · [Русский](TELEGRAM_RU.md)

`guard --telegram` — пульт с телефона. Только `TELEGRAM_CHAT_ID`.

## Console unlock (v0.4)

Если утёк `.env` (token + chat_id), злоумышленник всё равно не должен жать kill/ban без доступа к консоли хоста.

1. При старте `guard --telegram` в **консоли** печатается 6-значный код (в текст TG-сообщения код не кладётся).
2. В TG: контроль **LOCKED** → `/unlock 123456`.
3. Сессия на `unlock_ttl_sec` (по умолчанию **2ч**). `/lock` — новый код в консоли.

**Также:** действия live web / Mini App (`/api/action`) сидят на той же сессии unlock. Unlock: TG `/unlock` **или** Settings в Mini App / `POST /api/unlock`. В LOCKED скрываются процессы и детали bans.

**Антибрут:** после 5 неверных кодов консоль печатает новый; после 8 за 5 минут — отказ до паузы / рестарта.

```yaml
telegram:
  require_console_unlock: true
  unlock_ttl_sec: 7200
```

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

## Live web / Mini App

HTTPS-туннель + `WEBAPP_URL` + `guard --web` → `/dashboard`. Пошагово: [WEBAPP_RU.md](WEBAPP_RU.md).

## См. также

[Рецепты CLI](RECIPES_RU.md) · [Config](CONFIG_RU.md) · [Live web](WEBAPP_RU.md)
