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
sudo apt-get update
sudo apt-get install -y python3 python3-venv curl minisign
```

Нужен `sudo` (или root). Linux x86_64.

### 1.2 Never-ban своего IP (до soft/full банов)

Чтобы защита не отрезала тебе SSH, свой IP должен быть в `response.never_ban_cidrs`.
Удобнее сделать после шага 1.4 командой `home seed-never-ban`. Если IP уже знаешь — запишешь в меню «Mode / never-ban» или через `home settings`.

### 1.3 Скачать подписанный day-0 скрипт и запустить

Бери **ассеты релиза** (есть `.minisig`). Не заливай неподписанный raw git в `sudo bash`.

```bash
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh.minisig"
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh "$TAG"
```

**Ожидание:** проверены wheel и musl-агент, venv в `~/.local/share/sysspectogram`, затем меню `python -m sysspectogram menu`.

**Если minisign ругается:** стоп. Перекачай пару файлов с того же релиза.

### 1.4 Настройка + never-ban + protect

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"

python -m sysspectogram configure
# или без вопросов:
# python -m sysspectogram configure --accept-recommended --role ssh

python -m sysspectogram home seed-never-ban

loginctl enable-linger "$USER"
python -m sysspectogram protect enable
python -m sysspectogram home health --ping
```

**Ожидание:** health ок, unit protect активен. Код unlock — в консоли / Control Center, не в Telegram-уведомлении о коде ([SECURITY.md](../SECURITY.md)).

### 1.5 Готово

Дальше по желанию: [Telegram](#telegram-бот) · [Веб-дашборд](#веб-дашборд) · [Десктоп](#b-desktop-control-center) · [eBPF-агент](#ebpf-integrity-агент).

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
2. Скачай бандл Control Center (`*.AppImage` / `*.deb`; имена вида `SysSpectogram_Control_Center_*_amd64.AppImage`). Проверь `SHA256SUMS.desktop` и `.minisig`, если они есть.
3. Запусти → **Install stack** (wheel + musl agent того же тега; нужны `python3`+`venv`; **minisign** обязателен при наличии `.minisig`).
4. Онбординг: язык, режим, **never-ban**, Telegram.
5. Home → **Start protection**. При необходимости: `loginctl enable-linger $USER`.
6. Опционально: Settings → install helper (pkexec).

[FRIEND.md](FRIEND.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [HOME.md](HOME.md).

Из checkout (разработка):

```bash
sudo scripts/install-helper.sh
cd control-center && npm install && npm run tauri dev
```

---

## C. Fleet Hub

Админский ПК + SSH на VPS. [FLEET_HUB.md](FLEET_HUB.md) · [FLEET.md](FLEET.md).

- Бандл **SysSpectogram Fleet Hub** с того же релиза (`AppImage`/`deb`/`dmg`/`exe` как опубликовано).
- Или venv + wheel, `SYSSPECTOGRAM_HOME=…`, `python -m sysspectogram fleet …`.
- Pair: `home pair-remote` / `home pair-complete`.

Never-ban и unlock — **на каждом хосте**.

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
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

[GOLDEN_PATH.md](GOLDEN_PATH.md) · [CONFIGURE.md](CONFIGURE.md).

---

## E. Docker

Есть `Dockerfile` / `Dockerfile.onnx` для **train/analyze**. Compose для боевого guard нет. Для защиты на хосте используй A–D.

---

## Telegram-бот

Секреты только в `.env` с правами **0600** или через UI — не в чат.

```bash
python -m sysspectogram home env --from-stdin <<'EOF'
{"bot_token":"PASTE_TOKEN","chat_id":"PASTE_CHAT_ID"}
EOF
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

[TELEGRAM.md](TELEGRAM.md). Опасные действия — после **unlock**.

---

## Веб-дашборд

```bash
python -m sysspectogram guard --model artifacts/real_v3 --web --dry-run
```

По умолчанию loopback. Туннель → нужен `public_url` и auth. Мутации: сессия или Bearer из `state/web.token` (0600). [SECURITY.md](../SECURITY.md).

---

## eBPF integrity агент

Ассет: `sysspectogram-agent-x86_64-linux-musl` (+ `.sha256`, `.minisig`). Ставится day-0 / Install stack. Из исходников: `agent/` + `python -m sysspectogram kirk trust`. [KIRK.md](KIRK.md) · [AGENT_PROTECT.md](AGENT_PROTECT.md).

---

## Cloudflare Edge

Опциональный Under Attack, не scrubber. Токен с правом **Zone.Zone Settings:Edit** на **одну** зону. `python -m sysspectogram edge status` / `under-attack --yes` / `clear --yes`. [EDGE.md](EDGE.md).

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

1. **Отрезал себе SSH** — консоль хостера; режим `observe` или расширь never_ban через `home settings`; never_ban **до** soft/full.
2. **Нет python3-venv** — `sudo apt-get install -y python3-venv`.
3. **Нет minisign** — установи пакет; подписи обязательны при `.minisig`.
4. **Не сходится подпись** — неверный тег/файл; не обходи проверку.
5. **Protect гаснет после logout** — `loginctl enable-linger $USER`.
6. **Нет nft** — поставь nftables; начни с `--dry-run`.
7. **polkit не спрашивает пароль** — нужен desktop agent или `sudo bash` в обычном терминале.
8. **Порт занят** — смени `web.port` / освободи порт осознанно.
9. **Разные версии** — AppImage, wheel и agent одного тега.
10. **`home env` ругается** — формат токена `digits:secret`, без переносов строк.

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
python -m sysspectogram protect stop
python -m sysspectogram protect disable

sudo systemctl disable --now sysspectogram-helper.service
sudo rm -f /usr/lib/sysspectogram/sysspectogram-helper \
  /etc/systemd/system/sysspectogram-helper.service \
  /usr/share/polkit-1/actions/org.sysspectogram.helper.policy \
  /usr/lib/sysusers.d/sysspectogram.conf \
  /usr/share/sysspectogram/minisign.pub
sudo systemctl daemon-reload
```

Данные в `SYSSPECTOGRAM_HOME` удаляй отдельно. Модель угроз: [THREAT_MODEL.md](THREAT_MODEL.md).
