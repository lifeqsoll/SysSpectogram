# Install SysSpectogram

**Tag:** replace `<LATEST_TAG>` with the newest release name from
[github.com/lifeqsoll/SysSpectogram/releases/latest](https://github.com/lifeqsoll/SysSpectogram/releases/latest)
(example shape: `v1.3.2`). Do **not** install from floating `main`.

**Pubkey (minisign):** `RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F`  
(same as release asset `SysSpectogram.minisign.pub` and scripts’ `MINISIGN_PUB_B64`)

Related: [INSTALL_RU.md](INSTALL_RU.md) · [INSTALL_WITH_AI.md](INSTALL_WITH_AI.md) · [FRIEND.md](FRIEND.md) · [SECURITY.md](../SECURITY.md)

---

## 1. Quick start (one Ubuntu/Debian VPS)

Best default: one server, SSH + alerts, no desktop. ~15 minutes.

### 1.1 Prerequisites

```bash
# 1 — package index
sudo apt-get update
# 2 — Ubuntu: minisign lives in universe
sudo apt-add-repository -y universe 2>/dev/null || true
sudo apt-get install -y python3 python3-venv curl minisign
```

You need `sudo` (or root). x86_64 Linux.

### 1.2 Download signed day-0 script and run it

Prefer **release assets** (have `.minisig`). Do not pipe unsigned raw git into `bash`.

```bash
# 1 — pick tag from releases/latest, then download the pair
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh.minisig"
# 2 — verify and run (optional: bash friend-day0.sh "$TAG" --no-menu on releases that ship it)
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh "$TAG"
```

**Expect:** wheel + musl agent verified, venv under `~/.local/share/sysspectogram`, then interactive `python -m sysspectogram menu`.

**After the menu opens:** press **0** (Quit) to return to the shell and continue §1.3, or use `bash friend-day0.sh "$TAG" --no-menu` when your release script supports it.

**If minisign fails:** stop. Wrong file or wrong tag — re-download from that release.

### 1.3 Configure + never-ban + protect

Never-ban your **admin SSH source IP** (`response.never_ban_cidrs`) **before** `protect enable` and **before** soft/full/isolate bans. On the VPS, `${SSH_CONNECTION%% *}` (or `${SSH_CLIENT%% *}`) is usually your laptop’s public IP — not bare `seed-never-ban` without `--ip` (that detects VPS egress).

On **Windows**, check the laptop IP from PowerShell: `curl.exe -4 ifconfig.me`.

```bash
# 1 — venv + configure
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram configure
# or: python -m sysspectogram configure --accept-recommended --role ssh
```

```bash
# 1 — dry-run: confirm the IP is YOUR admin PC, not the VPS
python -m sysspectogram home seed-never-ban --dry-run --ip "${SSH_CONNECTION%% *}"
# 2 — write never_ban, then enable protect (linger first)
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
loginctl enable-linger "$USER"
python -m sysspectogram protect enable
python -m sysspectogram home health --ping
```

**Health JSON:** top-level `"ok": false` is **normal** right after install when optional pieces are missing. Typical OK-to-ignore checks: `helper` unreachable (no privileged helper), `telegram not configured`, stale/empty `metrics` until protect has run a minute. Warnings that matter before soft/full: empty `never_ban`, `guard not running` after `protect enable`. Re-run health after protect is active.

Unlock code appears in console / Control Center when the gate is on — never in Telegram notice alone ([SECURITY.md](../SECURITY.md)).

### 1.4 Switch observe → soft (after never-ban)

When `home warmup` / health shows never-ban populated and protect is running:

```bash
python -m sysspectogram home settings --changes '{"response.mode":"soft"}'
python -m sysspectogram home health --ping
```

Stay on **observe** until never-ban is correct; soft/full without it can lock you out.

### 1.5 Done

Optional next: [Telegram](#telegram-bot) · [Web dashboard](#web-dashboard) · [Desktop app](#b-desktop-control-center) · [eBPF agent](#ebpf-integrity-agent).

---

## 2. Pick your path

| If you… | Go to |
|--------|--------|
| One VPS/VDS, SSH only | [A. Headless VPS](#a-headless-vps) or Quick start above |
| Linux PC with a desktop | [B. Desktop (Control Center)](#b-desktop-control-center) |
| Many servers from one admin PC | [C. Fleet Hub](#c-fleet-hub) |
| Develop / build from git | [D. Source install](#d-source-install) |
| Train/analyze in containers only | [E. Docker](#e-docker) |

**Add-ons** (any path): [Telegram](#telegram-bot) · [Web](#web-dashboard) · [eBPF](#ebpf-integrity-agent) · [Cloudflare Edge](#cloudflare-edge) · [Own ML model](#own-ml-model).

| Path | Who | Needs | Time |
|------|-----|-------|------|
| A Headless | VPS operators | Ubuntu/Debian-like, ~1+ GiB RAM, x86_64 | ~15–30 min |
| B Desktop | Home/lab Linux GUI | AppImage or `.deb`, python3+venv for Install stack | ~10–20 min |
| C Fleet | Multi-VPS admins | Admin Linux PC + SSH to hosts | ~30–60 min |
| D Source | Developers | git, Python 3.10+, optional Rust/cargo | ~30+ min |
| E Docker | Offline train/analyze | Docker; **not** recommended for live guard without host netns | varies |

---

## A. Headless VPS

Same as Quick start. Details: [FRIEND.md](FRIEND.md) · geek git Day-0: [DAY0_VPS.md](DAY0_VPS.md) · cold/air-gap: [COLD_INSTALL.md](COLD_INSTALL.md).

**Optional privileged helper** (polkit; system overlays / service control):

```bash
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh.minisig"
minisign -Vm install-helper-from-release.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
sudo bash install-helper-from-release.sh "$TAG"
```

**Expect:** `sysspectogram-helper.service` active; socket `/run/sysspectogram/helper.sock`; pubkey at `/usr/share/sysspectogram/minisign.pub`. Log out/in so group `sysspectogram` applies.

**Check:**

```bash
systemctl --no-pager status sysspectogram-helper.service
```

---

## B. Desktop (Control Center)

1. Open [releases/latest](https://github.com/lifeqsoll/SysSpectogram/releases/latest).
2. Download **Control Center** Linux bundle (`*.AppImage` or `*.deb`; names like `SysSpectogram_Control_Center_*_amd64.AppImage`). If that release has **no** desktop AppImage/deb/`.minisig`, **stop** — do not guess URLs or older tags; pick another release or wait for CI assets.
3. Verify when `.minisig` is published (same pubkey as day-0):

```bash
# 1 — example for AppImage; repeat for .deb if you use the package instead
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/SysSpectogram_Control_Center_${TAG}_amd64.AppImage.minisig"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/SysSpectogram_Control_Center_${TAG}_amd64.AppImage"
# 2 — verify (adjust filename to match the asset you downloaded)
minisign -Vm "SysSpectogram_Control_Center_${TAG}_amd64.AppImage" -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
```

   Optional: `SHA256SUMS.desktop` + `.minisig` when published.
4. Run the app → **Install stack** (downloads same-tag wheel + musl agent; needs `python3` + `venv`; **minisign** required when `.minisig` is present).
5. Onboarding: language, mode, **never-ban IPs**, Telegram.
6. Home → **Start protection** (user systemd, not dry-run). If needed: `loginctl enable-linger $USER`.
7. Optional: Settings → install helper from release (pkexec).

Details: [FRIEND.md](FRIEND.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [HOME.md](HOME.md).

**Dev from checkout** (not the friend path):

```bash
sudo scripts/install-helper.sh
cd control-center && npm install && npm run tauri dev
```

---

## C. Fleet Hub

Admin PC runs Fleet Hub / CLI; each VPS is a host. See [FLEET_HUB.md](FLEET_HUB.md) · [FLEET.md](FLEET.md) · [FLEET_CLI.md](FLEET_CLI.md).

**On the admin PC** (venv + release wheel or Fleet Hub bundle from `<LATEST_TAG>`):

```bash
# 1 — suggest host key, then start pairing over SSH
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram fleet keyscan --ssh user@vps1
python -m sysspectogram fleet pair-start --ssh user@vps1 --label vps1 \
  --host-key-line 'ssh-ed25519 AAAA…'
```

```bash
# 1 — finish pair + register host; 2 — check fleet
python -m sysspectogram fleet pair-finish --ssh user@vps1 --code PAIRCODE \
  --id vps1 --label "VPS 1" --host-key-line 'ssh-ed25519 AAAA…'
python -m sysspectogram fleet status --scope all
```

**On each VPS** (SSH session), before soft/full on that host:

```bash
source "${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}/.venv/bin/activate"
python -m sysspectogram home seed-never-ban --dry-run --ip "${SSH_CONNECTION%% *}"
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
```

Never-ban and unlock apply **per host**. Mutating fleet SSH needs `fleet pin-host --id … --host-key-line '…'` (or `--host-key-line` on `pair-start` / `pair-finish`).

---

## D. Source install

```bash
git clone https://github.com/lifeqsoll/SysSpectogram.git
cd SysSpectogram
git checkout <LATEST_TAG>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[onnx]"   # or -e ".[dev]" for tests

python -m sysspectogram configure
# or: python -m sysspectogram configure --accept-recommended --role ssh

python -m sysspectogram home seed-never-ban
# Optional agent from source:
#   cd agent && cargo build --release && cd ..
#   python -m sysspectogram kirk trust
python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

Golden lab smoke: [GOLDEN_PATH.md](GOLDEN_PATH.md). Configure details: [CONFIGURE.md](CONFIGURE.md).

---

## E. Docker

Dockerfiles exist for **train/analyze** (`Dockerfile`, `Dockerfile.onnx`). There is **no** compose file for a live guard. Live `guard`/`monitor` on Docker without host networking/nft is unsupported for production. Prefer A–D for protection.

---

## Telegram bot

1. Create a bot with **[@BotFather](https://t.me/BotFather)**; send `/start` to your bot and read **chat id** (or use `@userinfobot` / Bot API `getUpdates`).
2. Put secrets in `.env` (mode **0600**) or Control Center / `configure` / menu — never paste tokens into public chats or AI threads.

```bash
# 1 — type secrets locally (no heredoc in copy-paste guides)
read -rsp "Bot token: " BOT; echo
read -rsp "Chat id: " CHAT; echo
# 2 — pipe JSON on stdin; writes 0600 .env under SYSSPECTOGRAM_HOME
printf '{"bot_token":"%s","chat_id":"%s"}\n' "$BOT" "$CHAT" | python -m sysspectogram home env --from-stdin
```

Friend path (no custom ML dir required):

```bash
python -m sysspectogram guard --telegram --dry-run
```

More: [TELEGRAM.md](TELEGRAM.md). Destructive actions need console **unlock** code.

---

## Web dashboard

```bash
python -m sysspectogram guard --web --dry-run
# or combine: --telegram --web
```

Bind is loopback by default. If you expose via tunnel, set `public_url` and auth (Mini App / session). Mutations need a session or Bearer from `state/web.token` (0600). See [SECURITY.md](../SECURITY.md).

---

## eBPF integrity agent

Release asset: `sysspectogram-agent-x86_64-linux-musl` (+ `.sha256`, `.minisig`). Friend day-0 / Control Center **Install stack** install it into the home `bin/`. Source: build under `agent/`, then `python -m sysspectogram kirk trust`. Caps and residual risk: [THREAT_MODEL.md](THREAT_MODEL.md) · [AGENT_PROTECT.md](AGENT_PROTECT.md) · [KIRK.md](KIRK.md).

---

## Cloudflare Edge

Optional Under Attack toggle — **not** a traffic scrubber. Token with **Zone.Zone Settings:Edit** on **one** zone only. In `.env` (0600): `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID` (see [EDGE.md](EDGE.md)). CLI: `python -m sysspectogram edge status` / `under-attack --yes` / `clear --yes`.

---

## Own ML model

Train elsewhere (GPU optional), ship ONNX / verified artifacts to the VPS. `python -m sysspectogram home import-model …` or place under `artifacts/live`. Bridge notes: [TRAIN_BRIDGE.md](TRAIN_BRIDGE.md). Prefer pickle-free runtime ([SECURITY.md](../SECURITY.md)).

---

## Checklist after install

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"   # friend path
python -m sysspectogram home health --ping
python -m sysspectogram protect status            # friend protect unit
# if helper installed:
systemctl is-active sysspectogram-helper.service
test -f /usr/share/sysspectogram/minisign.pub && echo helper-pubkey-ok
# never_ban non-empty before soft/full:
python -m sysspectogram home warmup
```

---

## Frequent problems

1. **Locked myself out of SSH** — Hoster VNC/serial console; then `python -m sysspectogram home settings --changes '{"response.mode":"observe"}'` (or widen `response.never_ban_cidrs`). Advanced: `sudo nft flush table inet sysspectogram` only if you understand existing rules. Prefer never_ban **before** soft/full.
2. **`python3-venv` missing** — `sudo apt-get install -y python3-venv`.
3. **`minisign: command not found`** — `sudo apt-get install -y minisign` (or install from jedisct1 releases). Signatures are mandatory when `.minisig` exists.
4. **Signature verify failed** — Wrong tag/asset; re-download pair from the same release; do not skip verify.
5. **Protect dies on SSH logout** — `loginctl enable-linger $USER`.
6. **No nft / cannot ban** — Install nftables; start with `--dry-run`; check permissions.
7. **polkit never asks password** — Need a desktop session + agent; or run helper install in a normal terminal with `sudo bash install-helper-from-release.sh …`.
8. **Web port busy** — Change `web.port` / free the port (`fuser -k <port>/tcp` only if you understand the impact).
9. **Version skew** — AppImage, wheel, and agent must be the **same** tag (ADR 0005).
10. **`home env` rejects token** — Format `digits:secret`; no newlines; file written 0600.
11. **Menu `EOFError` / non-interactive SSH** — Day-0 needs a TTY for the friend menu; press **0** to quit or use `--no-menu` when supported; run `configure` / §1.3 commands in an interactive SSH session (`ssh -t`).
12. **`home health` shows `"ok": false`** — Often normal without helper/Telegram/fresh metrics; see §1.3. After `protect enable`, `guard` should become reachable; install helper only if you need polkit overlays.

---

## Update (signed releases only)

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram home update --tag <LATEST_TAG>
```

Desktop: Settings → **Update stack from GitHub**, or re-run Install stack. Helper: re-run signed `install-helper-from-release.sh` for the new tag.

---

## Stop / remove / rollback

```bash
# 1 — stop friend protect (user systemd)
python -m sysspectogram protect stop
python -m sysspectogram protect disable
systemctl --user disable --now sysspectogram-protect.service 2>/dev/null || true
rm -f ~/.config/systemd/user/sysspectogram-protect.service
systemctl --user daemon-reload
```

```bash
# 1 — revoke paired device tokens on the VPS; 2 — remove helper if installed
python -m sysspectogram home remote-revoke --all
sudo systemctl disable --now sysspectogram-helper.service
sudo rm -f /usr/lib/sysspectogram/sysspectogram-helper \
  /etc/systemd/system/sysspectogram-helper.service \
  /usr/share/polkit-1/actions/org.sysspectogram.helper.policy \
  /usr/lib/sysusers.d/sysspectogram.conf \
  /usr/share/sysspectogram/minisign.pub
sudo systemctl daemon-reload
```

If present: remove `/etc/sysspectogram/` (helper overlay), `/etc/sysspectogram.env`, and distro units you added manually.

Bans: return mode to observe and clear nft (`inet sysspectogram`) from hoster console if locked out. Data stays under `SYSSPECTOGRAM_HOME` / `~/.local/share/sysspectogram` until you delete it.

Threat / trust model: [THREAT_MODEL.md](THREAT_MODEL.md) · [SECURITY.md](../SECURITY.md).
