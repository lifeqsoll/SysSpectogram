# Live web / Telegram Mini App

Тот же UI, что [demo на Pages](../demo/), но с **живыми** метриками хоста (и score модели, если задана). Браузер на ПК и [Telegram Mini App](https://core.telegram.org/bots/webapps) на телефоне.

Фейковый demo без установки: https://lifeqsoll.github.io/SysSpectogram/demo/

---

## Что должно быть в `.env`

```bash
TELEGRAM_BOT_TOKEN=…          # BotFather
TELEGRAM_CHAT_ID=…            # id личного чата (= твой user id)
TELEGRAM_TOKEN_SECRET=…       # стабильный HMAC для inline-кнопок (желательно)
WEBAPP_URL=https://….         # HTTPS URL туннеля (для телефона / Mini App)
```

Шаблон: `.env.example`. Файл `.env` **не коммитить**.

Бот и действия Mini App принимает **только** `TELEGRAM_CHAT_ID`. Остальные чаты игнорируются.

---

## 1. Дашборд на ПК

```bash
# только метрики
python -m sysspectogram web

# со scoring модели
python -m sysspectogram web --model artifacts/real_v3

# guard + Telegram + web одним процессом
python -m sysspectogram guard --model artifacts/real_v3 --telegram --web --dry-run
```

Открыть: **http://127.0.0.1:8765/**

- Тема тёмная по умолчанию; в шапке Light/Dark.
- С `127.0.0.1` можно смотреть и жать actions без Telegram-авторизации.
- Через публичный туннель — открывать из Telegram (`initData`), user id = `TELEGRAM_CHAT_ID`.

Хост/порт: секция `web:` в `configs/default.yaml` (оставь `host: 127.0.0.1`).

---

## 2. Что умеет UI

| Блок | Что делает |
| --- | --- |
| Графики | CPU / mem / net / disk (+ scores при модели) |
| Алерты | События; у карточек с IP — Ban / Allow / Mute / Recon |
| SOAR | Ban 1h/24h/perm, Unban, Allowlist, Mute, Quiet, Lockdown, Shield port, Kill PID, OSINT recon |
| Top processes | Список + Kill; кнопка Refresh |
| Settings | Переключатель `dry_run` (без реального nft/SIGKILL) |

Перед опасными действиями — confirm. С `--dry-run` или dry_run в Settings — только лог/текст.

---

## 3. Телефон: HTTPS-туннель (обязательно)

С телефона `localhost` ПК недоступен. Telegram требует **HTTPS**.

Должны работать **три** вещи:

1. `guard … --web` (или `web`) на порту **8765**
2. Процесс туннеля (варианты ниже)
3. `WEBAPP_URL` в `.env` = HTTPS URL туннеля → после смены URL **перезапусти** guard/web

У quick-tunnel хостнейм **меняется** при каждом рестарте туннеля — обновляй `WEBAPP_URL`.

### Вариант A — localtunnel (если Cloudflare режется сетью)

```bash
# отдельный терминал, не закрывать
npx --yes localtunnel --port 8765
# → your url is: https://something.loca.lt
```

В `.env`:

```bash
WEBAPP_URL=https://something.loca.lt
```

Перезапуск guard/web. Первый заход в браузере часто показывает **страницу-предупреждение**: впиши публичный IP хоста туннеля (он на этой странице, напр. `94.x.x.x`) → **Continue**. В WebView Telegram то же самое может всплыть один раз.

Для автоматизации: заголовок `bypass-tunnel-reminder: 1`.

### Вариант B — Cloudflare Tunnel

```bash
# Arch: sudo pacman -S cloudflared
# или ./tools/bin/cloudflared

cloudflared tunnel --protocol http2 --url http://127.0.0.1:8765
```

URL вида `https://….trycloudflare.com` → в `WEBAPP_URL`.

Если `TLS handshake with edge error: EOF` или страница **530** — сеть режет edge Cloudflare. Бери localtunnel / ngrok (иногда помогает VPN).

### Вариант C — ngrok

```bash
ngrok http 8765
# WEBAPP_URL=https://xxxx.ngrok-free.app
```

---

## 4. BotFather (кнопка / Mini App)

По желанию, для меню бота:

1. [@BotFather](https://t.me/BotFather) → `/mybots` → бот → **Bot Settings** → Menu Button / Configure Mini App (формулировки меняются), либо `/newapp` / `/editapp`.
2. На вопрос **Web App URL** — тот же HTTPS, что в `WEBAPP_URL` (например `https://….loca.lt`).
3. Title: `Dashboard`. GIF можно пропустить.

Сам SysSpectogram при наличии `WEBAPP_URL` ставит menu button через API; в боте есть `/dashboard`.

---

## 5. С телефона в боте

1. В `.env` — token, chat id, `WEBAPP_URL`.
2. Туннель + `guard --telegram --web [--dry-run]` запущены.
3. Меню **Dashboard**, или `/dashboard`, или `/menu` → Open Dashboard.
4. Заходи только со своего allowlisted аккаунта.

---

## 6. Чеклист / если сломалось

| Симптом | Что сделать |
| --- | --- |
| Пустой Mini App / старый URL | Новый туннель → новый URL → `WEBAPP_URL` → рестарт guard |
| Страница пароля localtunnel | Ввести публичный IP хоста с той же страницы |
| Cloudflare 530 / TLS EOF | CF недоступен → localtunnel/ngrok/VPN |
| Actions 401 / тишина | Чужой чат; нужен `TELEGRAM_CHAT_ID` |
| Порт занят | Уже крутится другой web/guard; убить процесс или сменить `web.port` |
| Ban/kill «ничего не сделал» | Включён `dry_run` — выключи в Settings или убери `--dry-run` (осторожно) |

---

## Безопасность

- Web слушает `127.0.0.1`; наружу только HTTPS-туннель.
- Mini App: HMAC `initData` + allowlist `TELEGRAM_CHAT_ID`.
- Нет произвольного shell из UI; те же SOAR-действия, что в Telegram.
- Пока не уверен — держи `--dry-run`.

## Конфиг

`web:` в `configs/default.yaml` — `host`, `port`, `public_url` (опциональный оверрайд `WEBAPP_URL`).

## См. также

[Telegram](TELEGRAM_RU.md) · [Рецепты](RECIPES_RU.md) · [Config](CONFIG_RU.md) · [EN](WEBAPP.md)
