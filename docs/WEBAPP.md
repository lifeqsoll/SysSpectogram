# Live web dashboard + Telegram Mini App

Same look as the [GitHub Pages demo](demo/), but with **live** host metrics (and optional ML scores). Works in a PC browser and as a [Telegram Mini App](https://core.telegram.org/bots/webapps) on your phone.

Fake demo (no install): https://lifeqsoll.github.io/SysSpectogram/demo/

---

## What you need in `.env`

```bash
TELEGRAM_BOT_TOKEN=…          # BotFather
TELEGRAM_CHAT_ID=…            # your private chat id (= user id)
TELEGRAM_TOKEN_SECRET=…       # stable HMAC for TG inline buttons (optional but recommended)
WEBAPP_URL=https://….         # HTTPS tunnel URL for Mini App (phone only)
```

Copy from `.env.example`. **Never commit `.env`.**

Only `TELEGRAM_CHAT_ID` can use the bot and Mini App actions. Everyone else is ignored.

---

## 1. Local dashboard (PC)

```bash
# metrics only
python -m sysspectogram web

# with model scoring
python -m sysspectogram web --model artifacts/real_v3

# guard + Telegram + web in one process
python -m sysspectogram guard --model artifacts/real_v3 --telegram --web --dry-run
```

Open: **http://127.0.0.1:8765/**

- Theme: dark by default (Light/Dark toggle in the header).
- Loopback (`127.0.0.1`) can view and run actions without Telegram auth.
- Through a public tunnel you must open the app from Telegram so `initData` validates, and your user id must match `TELEGRAM_CHAT_ID`.

Port/host: `web:` in `configs/default.yaml` (keep `host: 127.0.0.1`).

---

## 2. What the UI does

| Area | Behavior |
| --- | --- |
| Live charts | CPU / mem / net / disk (+ scores when a model is loaded) |
| Alerts | Recent events; IP cards get Ban / Allow / Mute / Recon |
| SOAR controls | Ban 1h/24h/perm, Unban, Allowlist, Mute, Quiet, Lockdown, Shield port, Kill PID, OSINT recon |
| Top processes | List + Kill; Refresh button |
| Settings | Toggle `dry_run` (no real nft/SIGKILL when on) |

Confirm dialogs before destructive actions. With `--dry-run` (or Settings → dry_run) responses are logged only.

---

## 3. Phone: HTTPS tunnel (required)

Telegram Mini Apps need **HTTPS**. `http://127.0.0.1` on the PC is not reachable from the phone.

Keep **three** things running:

1. `guard … --web` (or `web`) on port **8765**
2. A tunnel process (see options below)
3. `WEBAPP_URL` in `.env` = that tunnel’s HTTPS URL → **restart** guard/web after changing it

Quick-tunnel hostnames **change** every restart → update `WEBAPP_URL` each time (or use a named tunnel / own domain).

### Option A — localtunnel (often works when Cloudflare is blocked)

```bash
# terminal: tunnel (leave running)
npx --yes localtunnel --port 8765
# → your url is: https://something.loca.lt
```

`.env`:

```bash
WEBAPP_URL=https://something.loca.lt
```

Restart guard/web. First visit in a browser may show a **security reminder**: enter the tunnel host public IP (shown on that page, e.g. `94.x.x.x`) → Continue. Telegram WebView may also show it once.

Bypass tip (automation only): header `bypass-tunnel-reminder: 1`.

### Option B — Cloudflare Tunnel

```bash
# Arch: sudo pacman -S cloudflared
# or use ./tools/bin/cloudflared if present

cloudflared tunnel --protocol http2 --url http://127.0.0.1:8765
```

Copy `https://….trycloudflare.com` into `WEBAPP_URL`.

If you see `TLS handshake with edge error: EOF` / page **530**, your network blocks Cloudflare edge — use localtunnel or ngrok instead (VPN sometimes fixes CF).

### Option C — ngrok

```bash
ngrok http 8765
# WEBAPP_URL=https://xxxx.ngrok-free.app
```

---

## 4. BotFather Mini App (menu / direct link)

Optional but nice for the side menu / Mini App menu button:

1. [@BotFather](https://t.me/BotFather) → `/mybots` → your bot → **Bot Settings** → **Menu Button** / **Configure Mini App** (wording varies), or `/newapp` / `/editapp`.
2. When asked for **Web App URL**, paste the **same** HTTPS URL as `WEBAPP_URL` (e.g. `https://….loca.lt`).
3. Title e.g. `Dashboard`. Skip GIF if you want.

SysSpectogram also sets a menu button via API when `WEBAPP_URL` is present, and exposes `/dashboard` in the bot.

---

## 5. Use from Telegram

1. `.env` has token, chat id, `WEBAPP_URL`.
2. Tunnel + `guard --telegram --web [--dry-run]` running.
3. In the bot: menu **Dashboard**, or `/dashboard`, or `/menu` → Open Dashboard.
4. Open only from your allowlisted account.

---

## 6. Checklist / troubleshooting

| Symptom | Fix |
| --- | --- |
| Mini App blank / old URL | Restart tunnel → new URL → update `WEBAPP_URL` → restart guard |
| localtunnel password page | Enter host public IP shown on the page |
| Cloudflare 530 / TLS EOF | Network blocks CF → localtunnel/ngrok/VPN |
| Actions 401 / ignored | Wrong chat; only `TELEGRAM_CHAT_ID` |
| Port in use | Another `web`/`guard --web`; kill stale process or change `web.port` |
| Ban/kill “did nothing” | `dry_run` still on — turn off in Settings or drop `--dry-run` (careful) |

---

## Security

- Bind web to `127.0.0.1`; expose only via HTTPS tunnel.
- Mini App: Telegram `initData` HMAC + allowlist `TELEGRAM_CHAT_ID`.
- No arbitrary shell from the UI; actions are the same SOAR-lite set as Telegram.
- Prefer `--dry-run` until you trust the setup.

## Config

`web:` in `configs/default.yaml` — `host`, `port`, `public_url` (optional override for `WEBAPP_URL`).

## See also

[Telegram bot](TELEGRAM.md) · [Recipes](RECIPES.md) · [Config](CONFIG.md)
