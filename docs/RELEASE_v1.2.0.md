# SysSpectogram v1.2.0 — Fleet (many VPS) + lasting unlock + TG charts

Follow-up to [v1.1.1](RELEASE_v1.1.1.md). This release is for people who run **more than one** Linux VPS and want one admin laptop (Control Center + CLI) and optional hub Telegram — without a public HTTPS control API.

Companion guide: **[FLEET.md](FLEET.md)** · Friend path still: [FRIEND.md](FRIEND.md) · [HOME.md](HOME.md).

---

## Download

From the [v1.2.0 GitHub Release](https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.2.0):

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.2.0_amd64.AppImage` / `.deb` | Desktop app (**Fleet** tab) |
| `sysspectogram-1.2.0-*.whl` + musl agent (+ sha256/minisig) | Stack (Install stack / day-0) |
| `sysspectogram-helper-x86_64-linux` (+ sha256/minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless one-liners |
| `sysspectogram-helper-packaging.tgz` | Unit + polkit for helper install |

Same-version rule ([ADR 0005](adr/0005-signed-bundle-not-git.md)): GUI, wheel, and agent must match this tag. Assets may appear a few minutes after the tag while CI finishes (helper often uploads first; wheel/agent/AppImage follow).

**Checksums:** stack installers (`friend-day0`, Install stack, `home update`) read **`SHA256SUMS`** (wheel + agent). Control Center AppImage/deb use **`SHA256SUMS.desktop`** — do not confuse the two.

---

## Who this is for

| You… | Use |
| --- | --- |
| One VPS, desktop | Same as v1.1 — AppImage → Install stack → Start protection |
| One VPS, SSH only | `friend-day0.sh` + linger (below) |
| **Many VPS**, one laptop | Pair each host → `fleet.json` → Control Center **Fleet** / `fleet …` / fleet Telegram hub |

Security model for remote control: **SSH + short pair code + device token**. No unlock/pair codes in Telegram. No “emergency pocket codes”.

---

## Install / upgrade

### Friend desktop

1. Download AppImage/`.deb` for **v1.2.0**.
2. **Install stack** (same tag) if prompted.
3. Onboarding → Start protection (or upgrade stack from Settings if you already run v1.1.x).
4. Optional: open **Fleet** after pairing hosts (see below).

### Headless VPS

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/friend-day0.sh | bash -s -- v1.2.0
loginctl enable-linger $USER
```

Optional helper:

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/install-helper-from-release.sh | sudo bash -s -- v1.2.0
```

---

## Highlights

### 1. Fleet — many hosts from one admin PC

- Registry: `~/.config/sysspectogram/fleet.json` (0600) — hosts, **primary**, groups, settings **profiles**, dependency **edges**
- Pair once per VPS:
  - On VPS: `home pair-remote --label laptop` → short pair code
  - On admin PC (SSH, within ~5 min): `home pair-complete CODE` → **store `device_token` once**
  - Register: `fleet add --id web1 --ssh user@host --home /path --device-token …`
- Fan-out: `fleet status` · `fleet unlock-locked` · `fleet attack` · `fleet release`
- Profiles: `fleet profile-set` / `profile-apply` (allowlisted `home settings` only — **cannot** set `response.mode=isolate`; that stays Attack)
- Graph: `fleet edge-add` / `fleet graph`; Attack `--deps` follows dependents, **never auto-includes bastion/dns**
- Warmup checklist before soft shield: `home warmup` / `fleet warmup`
- Control Center **Fleet** tab: table, edges, profiles, Warmup, Attack L2/L3 (+ deps), Release
- Optional **fleet Telegram hub** (`FLEET_TELEGRAM_BOT_TOKEN` / `FLEET_TELEGRAM_CHAT_ID`); each VPS keeps its own bot for single-host ops

Full walkthrough: [FLEET.md](FLEET.md).

### 2. Isolation ladder (Attack)

| Level | Effect | How |
| --- | --- | --- |
| Soft / L1 | IP ban after warmup (shield) | Auto only with auto-ban path — not “alert alone” |
| **L2** | Drop new inbound to app ports (default **80/443**); SSH OK | `fleet attack --scope web1 --level L2` |
| **L3** | Full inbound lockdown (needs never-ban) | `fleet attack --scope web1 --level L3` |
| Release | Clear quarantine / lockdown / kirk best-effort | `fleet release --scope web1` |

Alerts alone never cascade to L2/L3. Soft mitigation ≠ anti-DDoS — put CDN/scrubber in front of public sites if you need that.

### 3. Unlock that lasts

- Alphanumeric unlock code (~**5 min** TTL to enter)
- After `/unlock`, session stays open until `/lock` (and can survive guard restart via `state/control.unlocked`)
- You do **not** unlock every morning
- Mass unlock for LOCKED fleet hosts: Control Center → Fleet → **Unlock locked**, or `fleet unlock-locked` (reads `unlock.code` over SSH **on the admin PC only**)
- If Attack/Kill hits LOCKED: full EN/RU **playbook** (per-VPS bot / Fleet unlock / SSH `cat state/unlock.code`)

### 4. Telegram charts & safer kill

- `/charts` — CPU, memory, network, GPU, disk images (Pillow)
- Auto-kill is gated: only when the auto-ban / shield path is enabled (not a free-standing auto-kill)

### 5. Protect / control plane hardening

- Protect systemd unit uses `Path.absolute()` for the venv interpreter (avoids broken `resolve()` through symlinks → wrong system Python)
- After any device is paired, control.sock expects a **device token** (PEERCRED alone is not enough over SSH forward)
- Re-`fleet add` without `--device-token` **preserves** the existing token
- Mistyped pair codes return `bad pair code` (no crash on length mismatch)

### 6. Observability & fleet ops

- **Prometheus:** `prometheus.enabled` → `http://127.0.0.1:9108/metrics`; CLI `metrics serve|dump`
- **ML explain:** host alerts show top-3 metrics; TG **False positive**; Fleet `mark-fp`
- **Eval / schema:** `eval run|schema|stamp-schema`; train writes `schema_version`
- **Fleet feed:** `fleet incidents`; `fleet ban --ip` across scope

---

## Day-0 fleet sketch

On each VPS (once):

```bash
cd /path/to/SysSpectogram   # or home after friend-day0
.venv/bin/python -m sysspectogram home pair-remote --label laptop
```

On the admin PC:

```bash
ssh user@vps 'cd /path && .venv/bin/python -m sysspectogram home pair-complete PAIRCODE --label laptop'
# save device_token from JSON

.venv/bin/python -m sysspectogram fleet add \
  --id web1 --label "Web 1" --ssh user@vps \
  --home /path/to/SysSpectogram \
  --device-id … --device-token … --role primary

.venv/bin/python -m sysspectogram fleet status --scope all
.venv/bin/python -m sysspectogram fleet graph
```

Attack when you mean it:

```bash
.venv/bin/python -m sysspectogram fleet attack --scope web1 --level L2
.venv/bin/python -m sysspectogram fleet attack --scope web1 --level L2 --deps
.venv/bin/python -m sysspectogram fleet release --scope web1
```

---

## CLI additions (admin PC)

```text
fleet path | list | graph | add | primary | remove
fleet profile-set | profile-apply | group-set
fleet edge-add | edge-rm
fleet warmup [--scope local|all|host|group:…]
fleet status | unlock-locked | attack | release | tg
home pair-remote | pair-complete | remote-list | remote-revoke
home warmup | home settings
```

---

## Breaking / operator notes

- Pairing a remote device changes control auth on that host: local CC on the VPS should use a paired profile or understand the token gate ([FLEET.md](FLEET.md) safety section).
- L2/L3 on a public website IP = downtime for new clients on those ports / that host unless you have DNS/canary failover.
- Profiles must not silently isolate; use Attack for L2/L3.
- Unlock codes and pair codes must never be pasted into Telegram.

---

## Docs

[FLEET.md](FLEET.md) · [FRIEND.md](FRIEND.md) · [HOME.md](HOME.md) · [TELEGRAM.md](TELEGRAM.md) · [TELEGRAM_RU.md](TELEGRAM_RU.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [SECURITY.md](../SECURITY.md) · [v1.1.1](RELEASE_v1.1.1.md)
