# Simple home — Control Center first

SysSpectogram can run as a **simple self-hosted host guard** for a cheap VPS: install the desktop Control Center, answer a short onboarding survey, get plain-language alerts (EN or RU — same as the app language), and optionally Telegram.

The geek surface (schema settings, lab, scenarios, agent knobs) stays behind **Advanced** in Settings.

## Day-0 (desktop app)

**Friend path (recommended):** see **[FRIEND.md](FRIEND.md)** — AppImage/deb or headless one-liner for [v1.1.1](RELEASE_v1.1.1.md). Short version: download package → **Install stack** → onboarding (never-ban + Detect my IP) → finish enables **background protect**.

**From a git checkout (dev):**

1. Optional helper: `sudo scripts/install-helper.sh` or `install-helper-from-release.sh`.
2. Open Control Center (`cd control-center && npm run tauri dev` or a release build).
3. Complete onboarding → **background protect** (systemd --user). Session “Start” also enables that unit.

Defaults:

- `web.enabled: false` — charts live in the app; turn web on in Settings if you want the Mini App / browser UI.
- `telegram.enabled: false` until you save a bot token + chat id (Settings or wizard → `.env`).
- `response.mode` from the wizard / Settings: `observe` (notify only), `shield` (soft auto-ban), `aggressive` (full auto-ban), `isolate` (full + kirk network isolation on critical signals).
- `ui.lang: en|ru` — Telegram and in-app alert titles follow this.

## Never-ban your IP (`response.never_ban_cidrs`)

Auto-ban (soft / full / isolate) must not ban the address you SSH from.

1. On your laptop (or the VPS): `curl -4 ifconfig.me` → e.g. `203.0.113.10`
2. Control Center → **Settings** → **Never-ban IPs / CIDRs** — one or many (comma or one per line). Bare IP becomes `/32`.
   Example:
   ```
   203.0.113.10
   198.51.100.20/32
   ```
3. **Apply** → restart the guard (or Home → Start protection again)

Also available under Advanced → Response (`response.never_ban_cidrs`), or:

```bash
python -m sysspectogram home settings --changes '{"response.never_ban_cidrs":"203.0.113.10, 198.51.100.20/32"}'
```

Screenshots: [RELEASE_v1.1.0.md](RELEASE_v1.1.0.md). Current notes: [RELEASE_v1.1.1.md](RELEASE_v1.1.1.md).

## Telegram

1. Create a bot with BotFather, get your chat id.
2. Settings → paste token + chat id → **Save Telegram to .env**, enable Telegram, restart guard.
3. When unlock is required: Home → **Show code**, then `/unlock CODE` in the bot.
4. Ban / kill buttons in Telegram and in the app/web talk to the same response layer.

## Web UI (optional)

Enable **Web UI** in Settings (writes `web.enabled`), restart the guard. Open `http://127.0.0.1:8765/`. Light/dark themes, charts, alert cards with Ban / Allow / Mute / Kill — same unlock gate as Telegram.

## Machine learning (optional, separate machine)

**Collect metrics on this host** (the VPS you protect). **Train only on a separate builder PC** — training burns CPU and should not run on a small VPS.

On **this host**:

```bash
python -m sysspectogram collect --out data/normal.csv --duration 1800
# induce load or use simulations, then:
python -m sysspectogram collect --out data/anomaly_cpu.csv --duration 900
```

Copy the CSVs to a **builder PC**, then:

```bash
python -m sysspectogram build-dataset \
  --normal data/normal.csv --anomaly data/anomaly_cpu.csv \
  --out dataset/real --window 60 --stride 5
python -m sysspectogram train --dataset dataset/real --out artifacts/real --epochs 25
python -m sysspectogram export-onnx --model artifacts/real
```

Copy the model folder back to the VPS, then in Control Center Settings → **Import weights** (or CLI):

```bash
python -m sysspectogram home import-model /path/to/artifacts/real
```

Restart the guard so it picks up `artifacts/live` (or `state/model.path`). Prefer ONNX (`runtime.prefer: onnx` / `pip install -e '.[onnx]'`).

More detail: [FRIEND.md](FRIEND.md), [TRAIN_BRIDGE.md](TRAIN_BRIDGE.md). Geek git path: [DAY0_VPS.md](DAY0_VPS.md).

## Control socket

While the guard runs it listens on `state/control.sock`. Control Center and tooling use:

```bash
python -m sysspectogram control status
python -m sysspectogram control ban --ip 203.0.113.10 --ttl 3600
```

Destructive actions require console unlock when Telegram/web unlock is enabled.

## Related docs

- [CONTROL_CENTER.md](CONTROL_CENTER.md) — architecture and helper allowlist  
- [TELEGRAM.md](TELEGRAM.md) — bot commands  
- [WEBAPP.md](WEBAPP.md) — optional Mini App tunnel  
