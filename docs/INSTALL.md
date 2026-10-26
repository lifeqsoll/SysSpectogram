# Install SysSpectogram

**Tag:** replace `<LATEST_TAG>` with the newest release name from
[github.com/lifeqsoll/SysSpectogram/releases/latest](https://github.com/lifeqsoll/SysSpectogram/releases/latest)
(example shape: `v1.3.1`). Do **not** install from floating `main`.

**Pubkey (minisign):** `RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F`  
(same as release asset `SysSpectogram.minisign.pub` and scripts’ `MINISIGN_PUB_B64`)

Related: [INSTALL_RU.md](INSTALL_RU.md) · [INSTALL_WITH_AI.md](INSTALL_WITH_AI.md) · [FRIEND.md](FRIEND.md) · [SECURITY.md](../SECURITY.md)

---

## 1. Quick start (one Ubuntu/Debian VPS)

Best default: one server, SSH + alerts, no desktop. ~15 minutes.

### 1.1 Prerequisites

```bash
# tools used by the day-0 script and signature check
sudo apt-get update
sudo apt-get install -y python3 python3-venv curl minisign
```

You need `sudo` (or root). x86_64 Linux.

### 1.2 Never-ban your admin IP (do this before soft/full bans)

If soft/full/isolate mode bans scanners, your own SSH IP must be allowlisted
(`response.never_ban_cidrs`). Easiest after install (step 1.4); if you already
know your laptop public IP:

```bash
# after step 1.3 venv exists — or skip and use menu → Mode / never-ban
echo "Your admin IP will be written with: python -m sysspectogram home seed-never-ban"
```

### 1.3 Download signed day-0 script and run it

Prefer **release assets** (have `.minisig`). Do not pipe unsigned raw git.

```bash
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh.minisig"
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh "$TAG"
```

**Expect:** wheel + musl agent verified, venv under `~/.local/share/sysspectogram`, then interactive `python -m sysspectogram menu`.

**If minisign fails:** stop. Wrong file or wrong tag — re-download from that release.

### 1.4 Configure + never-ban + protect

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"

# Interactive Rich TUI in THIS terminal (not a browser)
python -m sysspectogram configure
# or non-interactive SSH role defaults:
# python -m sysspectogram configure --accept-recommended --role ssh

# Write your current public IP into never_ban (confirm the detected IP!)
python -m sysspectogram home seed-never-ban

# User systemd unit so protect survives logout
loginctl enable-linger "$USER"
python -m sysspectogram protect enable
python -m sysspectogram home health --ping
```

**Expect:** health JSON/`ok`, protect unit active. Unlock code appears in console / Control Center when the gate is on — never in Telegram notice alone ([SECURITY.md](../SECURITY.md)).

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
2. Download **Control Center** Linux bundle (`*.AppImage` or `*.deb` under that release; CI names look like `SysSpectogram_Control_Center_*_amd64.AppImage` / `.deb`). Prefer verifying with `SHA256SUMS.desktop` + `.minisig` when published.
3. Run the app → **Install stack** (downloads same-tag wheel + musl agent; needs `python3` + `venv`; **minisign** required when `.minisig` is present).
4. Onboarding: language, mode, **never-ban IPs**, Telegram.
5. Home → **Start protection** (user systemd, not dry-run). If needed: `loginctl enable-linger $USER`.
6. Optional: Settings → install helper from release (pkexec).

Details: [FRIEND.md](FRIEND.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [HOME.md](HOME.md).

**Dev from checkout** (not the friend path):

```bash
sudo scripts/install-helper.sh
cd control-center && npm install && npm run tauri dev
```

---

## C. Fleet Hub

Admin PC runs Fleet Hub / CLI; VPS are agents. See [FLEET_HUB.md](FLEET_HUB.md) · [FLEET.md](FLEET.md).

Typical pieces:

- Download **SysSpectogram Fleet Hub** bundle from the same release (`*.AppImage` / `.deb` / `.dmg` / `.exe` as published).
- Or: venv + release wheel, `SYSSPECTOGRAM_HOME=…`, then `python -m sysspectogram fleet …` (`pin-host`, `status`, …).
- Pair hosts: `python -m sysspectogram home pair-remote` / `home pair-complete` (see FLEET.md).

Never-ban and unlock still apply **per host**.

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

1. Create a bot with BotFather; note chat id.
2. Put secrets in project `.env` (mode **0600**) or Control Center / `configure` / menu — never paste tokens into public chats.

```bash
# after venv active; validates format; writes 0600 .env
python -m sysspectogram home env --from-stdin <<'EOF'
{"bot_token":"PASTE_TOKEN","chat_id":"PASTE_CHAT_ID"}
EOF

python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

More: [TELEGRAM.md](TELEGRAM.md). Destructive actions need console **unlock** code.

---

## Web dashboard

```bash
python -m sysspectogram guard --model artifacts/real_v3 --web --dry-run
# or combine: --telegram --web
```

Bind is loopback by default. If you expose via tunnel, set `public_url` and auth (Mini App / session). Mutations need a session or Bearer from `state/web.token` (0600). See [SECURITY.md](../SECURITY.md).

---

## eBPF integrity agent

Release asset: `sysspectogram-agent-x86_64-linux-musl` (+ `.sha256`, `.minisig`). Friend day-0 / Control Center **Install stack** install it into the home `bin/`. Source: build under `agent/`, then `python -m sysspectogram kirk trust`. Caps and residual risk: [THREAT_MODEL.md](THREAT_MODEL.md) · [AGENT_PROTECT.md](AGENT_PROTECT.md) · [KIRK.md](KIRK.md).

---

## Cloudflare Edge

Optional Under Attack toggle — **not** a traffic scrubber. Token with **Zone.Zone Settings:Edit** on **one** zone only. `.env`: `CLOUDFLARE_*`. CLI: `python -m sysspectogram edge status` / `under-attack --yes` / `clear --yes`. See [EDGE.md](EDGE.md).

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

1. **Locked myself out of SSH** — Use hoster VNC/serial console; set `response.mode` to `observe` or widen `response.never_ban_cidrs` via `home settings --changes '…'`; flush nft if you know the table (advanced). Prefer fixing never_ban **before** soft/full.
2. **`python3-venv` missing** — `sudo apt-get install -y python3-venv`.
3. **`minisign: command not found`** — `sudo apt-get install -y minisign` (or install from jedisct1 releases). Signatures are mandatory when `.minisig` exists.
4. **Signature verify failed** — Wrong tag/asset; re-download pair from the same release; do not skip verify.
5. **Protect dies on SSH logout** — `loginctl enable-linger $USER`.
6. **No nft / cannot ban** — Install nftables; start with `--dry-run`; check permissions.
7. **polkit never asks password** — Need a desktop session + agent; or run helper install in a normal terminal with `sudo bash install-helper-from-release.sh …`.
8. **Web port busy** — Change `web.port` / free the port (`fuser -k <port>/tcp` only if you understand the impact).
9. **Version skew** — AppImage, wheel, and agent must be the **same** tag (ADR 0005).
10. **`home env` rejects token** — Format `digits:secret`; no newlines; file written 0600.

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
# Friend protect (user unit)
python -m sysspectogram protect stop
python -m sysspectogram protect disable

# Helper (if installed from release)
sudo systemctl disable --now sysspectogram-helper.service
sudo rm -f /usr/lib/sysspectogram/sysspectogram-helper \
  /etc/systemd/system/sysspectogram-helper.service \
  /usr/share/polkit-1/actions/org.sysspectogram.helper.policy \
  /usr/lib/sysusers.d/sysspectogram.conf \
  /usr/share/sysspectogram/minisign.pub
sudo systemctl daemon-reload
```

Bans: return mode to observe and clear nft rules you added (hoster console if locked out). Data stays under `SYSSPECTOGRAM_HOME` / `~/.local/share/sysspectogram` until you delete it.

Threat / trust model: [THREAT_MODEL.md](THREAT_MODEL.md) · [SECURITY.md](../SECURITY.md).
