# Установка SysSpectogram

**Тег:** вместо `<LATEST_TAG>` подставь имя последнего релиза со страницы
[github.com/lifeqsoll/SysSpectogram/releases/latest](https://github.com/lifeqsoll/SysSpectogram/releases/latest)
(вид: `v1.3.2`). **Не** ставь с плавающего `main`.

**Публичный ключ minisign:** `RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F`  
(тот же, что в ассете `SysSpectogram.minisign.pub` и в `MINISIGN_PUB_B64` скриптов)

Связанное: [INSTALL.md](INSTALL.md) · [INSTALL_WITH_AI.md](INSTALL_WITH_AI.md) · [FRIEND.md](FRIEND.md) · [SECURITY.md](../SECURITY.md)

---

## 1. Быстрый старт (один VPS Ubuntu/Debian)

Обычный случай: один сервер, SSH и алерты, без графики. ~15 минут.

### 1.1 Что нужно заранее

```bash
# 1 — индекс пакетов
sudo apt-get update
# 2 — Ubuntu: minisign в universe
sudo apt-add-repository -y universe 2>/dev/null || true
sudo apt-get install -y python3 python3-venv curl minisign
```

Нужен `sudo` (или root). Linux x86_64.

### 1.2 Скачать подписанный day-0 и запустить

Бери **ассеты релиза** (есть `.minisig`). Не заливай неподписанный raw git в `bash`.

```bash
# 1 — тег с releases/latest, скачай пару файлов
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh.minisig"
# 2 — проверка и запуск (опционально: bash friend-day0.sh "$TAG" --no-menu)
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh "$TAG"
```

**Ожидание:** wheel + musl-агент, venv в `~/.local/share/sysspectogram`, затем меню `python -m sysspectogram menu`.

**После меню:** нажми **0** (Выход) и продолжай §1.3, либо `bash friend-day0.sh "$TAG" --no-menu`, если скрипт релиза это поддерживает.

**Если minisign ругается:** стоп. Перекачай с того же релиза.

### 1.3 Настройка + never-ban + protect

Свой **админский SSH IP** (`response.never_ban_cidrs`) нужно записать **до** `protect enable` и **до** soft/full/isolate. На VPS `${SSH_CONNECTION%% *}` (или `${SSH_CLIENT%% *}`) — обычно IP ноутбука, а не голый `seed-never-ban` без `--ip` (он смотрит egress VPS).

На **Windows** с ноутбука: `curl.exe -4 ifconfig.me`.

```bash
# 1 — venv + configure
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram configure
# или: python -m sysspectogram configure --accept-recommended --role ssh
```

```bash
# 1 — dry-run: IP должен быть твоим админским ПК
python -m sysspectogram home seed-never-ban --dry-run --ip "${SSH_CONNECTION%% *}"
# 2 — запись never_ban, linger, protect
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
loginctl enable-linger "$USER"
python -m sysspectogram protect enable
python -m sysspectogram home health --ping
```

**Health JSON:** `"ok": false` **нормально** сразу после установки без helper/Telegram/свежих метрик. Можно игнорировать: `helper` недоступен, `telegram not configured`, пустые/устаревшие `metrics`. Важно до soft/full: пустой never_ban, `guard not running` после `protect enable`.

Код unlock — в консоли / Control Center, не в Telegram ([SECURITY.md](../SECURITY.md)).

### 1.4 Переключить observe → soft (после never-ban)

Когда never-ban заполнен и protect работает:

```bash
python -m sysspectogram home settings --changes '{"response.mode":"soft"}'
python -m sysspectogram home health --ping
```

Оставайся на **observe**, пока never-ban не проверен.

### 1.5 Готово

Дальше: [Telegram](#telegram-бот) · [Веб-дашборд](#веб-дашборд) · [Десктоп](#b-desktop-control-center) · [eBPF-агент](#ebpf-integrity-агент).

---

## 2. Выбери свой вариант

| Если… | Раздел |
|------|--------|
| Один VPS без графики | [A. Headless VPS](#a-headless-vps) или быстрый старт |
| Linux-ПК с рабочим столом | [B. Desktop](#b-desktop-control-center) |
| Несколько серверов | [C. Fleet Hub](#c-fleet-hub) |
| Сборка из исходников | [D. Source](#d-source-install) |
| Train/analyze в контейнере | [E. Docker](#e-docker) |

Дополнения: [Telegram](#telegram-бот) · [Веб](#веб-дашборд) · [eBPF](#ebpf-integrity-агент) · [Cloudflare Edge](#cloudflare-edge) · [Своя ML-модель](#своя-ml-модель).

| Путь | Кому | Требования | Время |
|------|------|------------|-------|
| A | Операторы VPS | Ubuntu/Debian-подобные, ~1+ ГиБ RAM, x86_64 | ~15–30 мин |
| B | Домашний/лаб GUI | AppImage или `.deb`, python3+venv для Install stack | ~10–20 мин |
| C | Много VPS | Админский Linux + SSH | ~30–60 мин |
| D | Разработка | git, Python 3.10+, опционально Rust | ~30+ мин |
| E | Обучение моделей | Docker; **не** для боевого guard без host netns | по задаче |

---

## A. Headless VPS

То же, что быстрый старт. Подробности: [FRIEND.md](FRIEND.md) · git Day-0: [DAY0_VPS.md](DAY0_VPS.md) · холодная установка: [COLD_INSTALL.md](COLD_INSTALL.md).

**Опциональный privileged helper:**

```bash
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh.minisig"
minisign -Vm install-helper-from-release.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
sudo bash install-helper-from-release.sh "$TAG"
```

**Ожидание:** `sysspectogram-helper.service`, сокет `/run/sysspectogram/helper.sock`, ключ `/usr/share/sysspectogram/minisign.pub`. Перелогинься ради группы `sysspectogram`.

```bash
systemctl --no-pager status sysspectogram-helper.service
```

---

## B. Desktop (Control Center)

1. Открой [releases/latest](https://github.com/lifeqsoll/SysSpectogram/releases/latest).
2. Скачай Control Center (`*.AppImage` / `*.deb`). Если в **этом** релизе **нет** desktop AppImage/deb/`.minisig` — **стоп**, не придумывай URL и старые теги.
3. Проверка `.minisig` (тот же pubkey, что у day-0):

```bash
# 1 — пример AppImage; для .deb замени имена файлов
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/SysSpectogram_Control_Center_${TAG}_amd64.AppImage.minisig"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/SysSpectogram_Control_Center_${TAG}_amd64.AppImage"
# 2 — verify
minisign -Vm "SysSpectogram_Control_Center_${TAG}_amd64.AppImage" -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
```

   Опционально: `SHA256SUMS.desktop` + `.minisig`.
4. Запусти → **Install stack** (wheel + musl agent того же тега; `python3`+`venv`; **minisign** при `.minisig`).
5. Онбординг: язык, режим, **never-ban**, Telegram.
6. Home → **Start protection**. При необходимости: `loginctl enable-linger $USER`.
7. Опционально: Settings → install helper (pkexec).

[FRIEND.md](FRIEND.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [HOME.md](HOME.md).

Из checkout (разработка):

```bash
sudo scripts/install-helper.sh
cd control-center && npm install && npm run tauri dev
```

---

## C. Fleet Hub

Админский ПК + SSH на VPS. [FLEET_HUB.md](FLEET_HUB.md) · [FLEET.md](FLEET.md) · [FLEET_CLI.md](FLEET_CLI.md).

**На админ-ПК** (venv + wheel или Fleet Hub с `<LATEST_TAG>`):

```bash
# 1 — keyscan и pair-start по SSH
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram fleet keyscan --ssh user@vps1
python -m sysspectogram fleet pair-start --ssh user@vps1 --label vps1 \
  --host-key-line 'ssh-ed25519 AAAA…'
```

```bash
# 1 — pair-finish; 2 — статус флота
python -m sysspectogram fleet pair-finish --ssh user@vps1 --code PAIRCODE \
  --id vps1 --label "VPS 1" --host-key-line 'ssh-ed25519 AAAA…'
python -m sysspectogram fleet status --scope all
```

**На каждом VPS** до soft/full:

```bash
source "${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}/.venv/bin/activate"
python -m sysspectogram home seed-never-ban --dry-run --ip "${SSH_CONNECTION%% *}"
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
```

Never-ban и unlock — **на каждом хосте**. Мутирующий SSH: `fleet pin-host --id … --host-key-line '…'`.

---

## D. Source install

```bash
git clone https://github.com/lifeqsoll/SysSpectogram.git
cd SysSpectogram
git checkout <LATEST_TAG>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[onnx]"

python -m sysspectogram configure
# или: python -m sysspectogram configure --accept-recommended --role ssh

python -m sysspectogram home seed-never-ban
# Опционально агент из исходников:
#   cd agent && cargo build --release && cd ..
#   python -m sysspectogram kirk trust
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

[GOLDEN_PATH.md](GOLDEN_PATH.md) · [CONFIGURE.md](CONFIGURE.md).

---

## E. Docker

Есть `Dockerfile` / `Dockerfile.onnx` для **train/analyze**. Compose для боевого guard нет. Для защиты на хосте используй A–D.

---

## Telegram-бот

1. Бот через **[@BotFather](https://t.me/BotFather)**; **chat id** — после `/start` или через `@userinfobot` / `getUpdates`.
2. Секреты только в `.env` (**0600**) или UI — не в чат и не в ИИ.

```bash
# 1 — ввод локально (без heredoc в гайде)
read -rsp "Bot token: " BOT; echo
read -rsp "Chat id: " CHAT; echo
# 2 — stdin → home env
printf '{"bot_token":"%s","chat_id":"%s"}\n' "$BOT" "$CHAT" | python -m sysspectogram home env --from-stdin
```

Friend path (без своей ML-папки):

```bash
python -m sysspectogram guard --telegram --dry-run
```

[TELEGRAM.md](TELEGRAM.md). Опасные действия — после **unlock**.

---

## Веб-дашборд

```bash
python -m sysspectogram guard --web --dry-run
```

По умолчанию loopback. Туннель → нужен `public_url` и auth. Мутации: сессия или Bearer из `state/web.token` (0600). [SECURITY.md](../SECURITY.md).

---

## eBPF integrity агент

Ассет: `sysspectogram-agent-x86_64-linux-musl` (+ `.sha256`, `.minisig`). Friend day-0 / Install stack кладут бинарник в `bin/` домашней установки. Из исходников: `cd agent && cargo build --release`, затем `python -m sysspectogram kirk trust`. [THREAT_MODEL.md](THREAT_MODEL.md) · [AGENT_PROTECT.md](AGENT_PROTECT.md) · [KIRK.md](KIRK.md).

---

## Cloudflare Edge

Опциональный Under Attack, не scrubber. Токен **Zone.Zone Settings:Edit** на **одну** зону. В `.env` (0600): `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID` ([EDGE.md](EDGE.md)). CLI: `edge status` / `under-attack --yes` / `clear --yes`.

---

## Своя ML-модель

Учишь отдельно, на VPS — ONNX / проверенные артефакты. `home import-model` или `artifacts/live`. [TRAIN_BRIDGE.md](TRAIN_BRIDGE.md).

---

## Чеклист после установки

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram home health --ping
python -m sysspectogram protect status
systemctl is-active sysspectogram-helper.service   # если ставил helper
python -m sysspectogram home warmup
```

---

## Частые проблемы

1. **Отрезал себе SSH** — консоль хостера; `home settings --changes '{"response.mode":"observe"}'` или расширь never_ban. Продвинуто: `sudo nft flush table inet sysspectogram`. Never_ban **до** soft/full.
2. **Нет python3-venv** — `sudo apt-get install -y python3-venv`.
3. **Нет minisign** — установи пакет; подписи обязательны при `.minisig`.
4. **Не сходится подпись** — неверный тег/файл; не обходи проверку.
5. **Protect гаснет после logout** — `loginctl enable-linger $USER`.
6. **Нет nft** — поставь nftables; начни с `--dry-run`.
7. **polkit не спрашивает пароль** — нужен desktop agent или `sudo bash` в обычном терминале.
8. **Порт занят** — смени `web.port` / освободи порт осознанно.
9. **Разные версии** — AppImage, wheel и agent одного тега.
10. **`home env` ругается** — формат `digits:secret`, без переносов строк.
11. **Меню `EOFError` / SSH без TTY** — нужен интерактивный SSH (`ssh -t`); **0** для выхода или `--no-menu`; дальше §1.3.
12. **`home health` → `"ok": false`** — часто норма без helper/Telegram/метрик; см. §1.3.

---

## Обновление

```bash
source "${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}/.venv/bin/activate"
python -m sysspectogram home update --tag <LATEST_TAG>
```

Десктоп: Update stack / Install stack. Helper: снова подписанный `install-helper-from-release.sh`.

---

## Остановка и удаление

```bash
# 1 — user systemd protect
python -m sysspectogram protect stop
python -m sysspectogram protect disable
systemctl --user disable --now sysspectogram-protect.service 2>/dev/null || true
rm -f ~/.config/systemd/user/sysspectogram-protect.service
systemctl --user daemon-reload
```

```bash
# 1 — отозвать device tokens; 2 — helper
python -m sysspectogram home remote-revoke --all
sudo systemctl disable --now sysspectogram-helper.service
sudo rm -f /usr/lib/sysspectogram/sysspectogram-helper \
  /etc/systemd/system/sysspectogram-helper.service \
  /usr/share/polkit-1/actions/org.sysspectogram.helper.policy \
  /usr/lib/sysusers.d/sysspectogram.conf \
  /usr/share/sysspectogram/minisign.pub
sudo systemctl daemon-reload
```

Если есть: `/etc/sysspectogram/`, `/etc/sysspectogram.env`, вручную добавленные unit’ы.

Данные в `SYSSPECTOGRAM_HOME` удаляй отдельно. Баны: режим observe + nft `inet sysspectogram`. [THREAT_MODEL.md](THREAT_MODEL.md) · [SECURITY.md](../SECURITY.md).
