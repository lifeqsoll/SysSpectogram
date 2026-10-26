# SysSpectogram v1.2.2 — Fleet hub hardening, Edge CDN, Fleet Center

Follow-up to [v1.2.1](RELEASE_v1.2.1.md). This release makes the **multi-VPS admin hub** safer and usable day-to-day: confirm gates, SSH token hygiene, host-key pinning, soft IP fan-out across the fleet, an honest **Edge / CDN** path for volumetric attacks (not nft theatre), automatic **never-ban** seeding when you ask for it, and a thin **Fleet Center** desktop app for hub-only workflows.

Companion docs:

| Doc | What |
| --- | --- |
| [FLEET.md](FLEET.md) | Multi-VPS ops, Attack ladder, soft IP fan-out vs Edge, safety |
| [FLEET_HUB.md](FLEET_HUB.md) | Admin PC install (Win/mac/Linux hub), XDG/APPDATA paths |
| [FLEET_CLI.md](FLEET_CLI.md) | Fleet / edge CLI surface and flags |
| [EDGE.md](EDGE.md) | Cloudflare Under Attack / playbook M |
| [HOST_MITIGATION.md](HOST_MITIGATION.md) | Soft mitigation ≠ anti-DDoS |
| [CONTROL_CENTER.md](CONTROL_CENTER.md) | CLI ↔ UI parity (incl. `edge`) |
| [FRIEND.md](FRIEND.md) | Friend day-0 / Install stack for this tag |

---

## Download

Assets appear on the [v1.2.2 release](https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.2.2) after CI finishes (helper often first; wheel / agent / AppImage follow).

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.2.2_amd64.AppImage` / `.deb` | Desktop app (Fleet tab + Edge panel + pair wizard) |
| `sysspectogram-1.2.2-*.whl` + musl agent (+ sha256/minisig) | Stack (Install stack / day-0 / `home update`) |
| `sysspectogram-helper-x86_64-linux` (+ sha256/minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless one-liners |
| `sysspectogram-helper-packaging.tgz` | Unit + polkit for helper install |

**Fleet Center** (thin hub-only app) ships from the repo tree (`fleet-center/`); build locally with `npm run tauri build` until a dedicated AppImage job is added to release CI.

Same-version rule ([ADR 0005](adr/0005-signed-bundle-not-git.md)): GUI, wheel, and agent must match this tag.

**Checksums:** stack installers read **`SHA256SUMS`** (wheel + agent). Control Center AppImage/deb use **`SHA256SUMS.desktop`**.

Do **not** use tag **v1.2.0** (broken install). Prefer **v1.2.2**; v1.2.1 remains the previous installable patch.

---

## Who this is for

| You… | Use |
| --- | --- |
| One VPS, desktop | AppImage → Install stack → Start protection (same as v1.2.1) |
| One VPS, SSH only | `friend-day0.sh` + linger |
| **Many VPS**, one laptop | Pair → pin host key → Fleet / Fleet Center / `fleet …` |
| Public site under DDoS risk | Put Cloudflare (or other CDN) in front; use **Edge** panel / `edge under-attack` |

Security model for remote control unchanged: **SSH + short pair code + device token**. No unlock/pair codes in Telegram. No public HTTPS control API. Soft host mitigation is **not** a scrubbing center.

---

## Install / upgrade

### Friend desktop

1. Download AppImage/`.deb` for **v1.2.2**.
2. **Install stack** for the **same** tag if prompted.
3. Onboarding → detect never-ban IP → Start protection.
4. Optional: Settings → **Fleet hub only** if this PC only manages remotes.
5. Optional: open **Fleet** → pair wizard / Edge.

### Headless VPS

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.2/scripts/friend-day0.sh | bash -s -- v1.2.2
loginctl enable-linger $USER
```

Optional helper:

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.2/scripts/install-helper-from-release.sh | sudo bash -s -- v1.2.2
```

From an existing install:

```bash
python -m sysspectogram home update --tag v1.2.2
```

### Admin hub (laptop)

See [FLEET_HUB.md](FLEET_HUB.md): OpenSSH Client, Python 3.10+, user venv + wheel, `fleet.json` under XDG / APPDATA / Application Support. No helper/polkit required on the hub for Fleet CLI.

Smoke checklist: [scripts/fleet-hub-smoke.md](../scripts/fleet-hub-smoke.md).

---

## Highlights

### 1. Fleet safety (must-have before mass ops)

| Guardrail | Behavior |
| --- | --- |
| Confirm gates | CLI: non-TTY needs `--yes` for attack / ban / unlock-locked / release / profile-apply. UI: type `ATTACK` / `BAN` / `UNLOCK` / `RELEASE` / `EDGE` (includes **L2**) |
| Token not in argv | Remote control payload (incl. `device_token`) on **SSH stdin**. `fleet add` prefers env `SYSSPECTOGRAM_DEVICE_TOKEN` or `--device-token-stdin` |
| Host key pin | Mutating SSH refuses hosts without `host_key_line` unless `FLEET_SSH_TOFU=1`. `fleet pin-host`, `fleet keyscan`. **pair-finish** also requires pin |
| SSH destination | `ssh -- user@host`; values starting with `-` rejected (option injection) |
| Result matrix | Per-host `ok` / `error` / `latency_ms` / `detail` in CLI JSON and Control Center table (`FleetOpReport`) |
| Token mask | `fleet list` / `graph` → `token_set` yes/no; raw token never in UI tables |

### 2. Soft IP fan-out (why fleet matters)

If one host sees a concrete attacker IP (SSH brute, port scan, small-N web abuse), ban that IP on **eligible fleet hosts** (scope), not only the victim — same actor usually hits the next box.

- UI: Ban IP on scope (confirm `BAN`)
- CLI: `fleet ban --ip A.B.C.D --scope all --yes`
- Respects per-host never-ban; skips OFFLINE; per-host results
- **Not** for volumetric / huge L7 botnets (thousands of IPs) — use Edge / CDN

Attack-class table and playbooks: [FLEET.md](FLEET.md).

**Policy (explicit):** soft fan-out is for *known concrete IPs*. Edge/CDN is for *volumetric*. Never auto-write `never_ban` from alerts.

### 3. Never-ban your own IP

Empty never-ban under soft/full/isolate locks you out of SSH.

- `python -m sysspectogram home seed-never-ban` — detect egress public IP, merge into `response.never_ban_cidrs` (explicit write)
- Onboarding: auto-detect into the field (you still Finish)
- Configure TUI: confirm seed
- Friend menu Never-ban: detected IP as default when empty
- `protect enable`: refuses non-observe if never-ban still empty (detect-only hint, no silent write)
- Guard logs a warning once if soft+ and never-ban empty
- NAT caveat: office/CGNAT IP may be shared — edit the list if needed

### 4. Edge / CDN (playbook M) — not a scrubber

Volumetric L3/L4 and huge L7 die **before** the VPS. SysSpectogram stays the host/fleet brain; Edge calls your CDN.

| Command | Effect |
| --- | --- |
| `edge status` | Linked? `security_level` + playbook text |
| `edge under-attack --yes` | Cloudflare zone `security_level=under_attack` |
| `edge clear --yes` | Restore (default `high`) |
| `edge playbook [--lang ru]` | Operator script when CDN is missing |

Hub `.env`:

```bash
CLOUDFLARE_API_TOKEN=…   # Zone Settings Edit
CLOUDFLARE_ZONE_ID=…
```

Control Center / Fleet Center: Edge panel (Status · Under Attack · Clear · Playbook M). Heuristic badge may suggest Edge when the incidents feed looks volumetric — **never** auto-enables CF.

### 5. Control Center Fleet UX

- **Pair wizard:** SSH → `pair-start` → show code → `pair-finish` → host in `fleet.json` (pin via keyscan)
- Incidents feed panel; group filter; primary badge; deps column
- Warmup / status / ban / mark-fp honor selected **scope** (not hardcoded local)
- Settings → **Fleet hub only** — nav = Fleet + Settings (hide local-protect chrome)

### 6. Fleet Telegram hub

- `FLEET_TELEGRAM_ALLOW_USERS` — comma-separated chat/user IDs; others ignored
- Prefer DM bots; putting a **group** chat ID in the allowlist lets every member pass the chat check — avoid that for destructive ops
- Attack **L3** from TG requires a second step: `/confirm_l3` within 60s
- Status lines read nested `detail` from structured fleet results

### 7. Fleet Center app (`fleet-center/`)

Thin Tauri 2 + Svelte 5 app (no helper / polkit / local protect):

| Hosts in `fleet.json` | Landing |
| --- | --- |
| **N=0** | Pair / add wizard only |
| **N=1** | Host shell (status, unlock, L2/L3, release, ban, incidents, warmup) |
| **N≥2** | Overview + mass ops + drill-down to the same host shell |

Edge panel always visible. Same confirm keywords as Control Center.

```bash
cd fleet-center
npm install
npm run tauri dev    # UI http://localhost:1421
```

### 8. Isolation ladder (unchanged product rules)

| Level | Effect | How |
| --- | --- | --- |
| Soft / L1 | IP ban after warmup (shield) | Soft path / `fleet ban` |
| **L2** | Drop new inbound to app ports (default 80/443); SSH OK | Attack L2 + confirm |
| **L3** | Full inbound lockdown (needs never-ban) | Attack L3 + typed confirm |
| Release | Clear quarantine / lockdown / kirk best-effort | Release + confirm |

Alerts alone never cascade to L2/L3. Soft mitigation ≠ anti-DDoS.

---

## What changed in detail (engineering)

### Fleet / SSH / store

- Structured per-host results (`sysspectogram/fleet/results.py`) for CLI JSON and UI tables.
- Mutating remote control over SSH: payload on stdin; destination validated (`ssh --`, reject leading `-`).
- Host-key pin required for mutating ops and `pair-finish` unless `FLEET_SSH_TOFU=1`.
- `fleet public_dict()` exposes `token_set` (boolean), not a masked `device_token` string.
- Soft IP ban fan-out across scope with never-ban respect and offline skip.

### Edge

- New `edge` CLI: `status` / `under-attack` / `clear` / `playbook`.
- Cloudflare Zone Settings API only (no pretend scrubber).
- Documented in [EDGE.md](EDGE.md) and CLI↔UI parity matrix.

### Never-ban seed

- Explicit `home seed-never-ban`; onboarding / TUI / friend menu helpers; protect enable refuses soft+ with empty never-ban (hint only).

### Control Center

- Pair wizard, incidents panel, group filter, scope-aware mass actions, Fleet hub only mode, Edge panel, confirm keywords for L2/EDGE.

### Fleet Center

- New thin Tauri app: N=0 / N=1 / N≥2 landings; same confirm model; Edge always available.

### Fleet Telegram

- Allowlist via `FLEET_TELEGRAM_ALLOW_USERS`.
- L3 requires `/confirm_l3` within 60s.
- Status/detail parsing for structured fleet reports.

### Docs / version / CI

- Version bump **1.2.1 → 1.2.2** (pyproject, `__init__`, Control Center, Fleet Center, friend scripts, AUR PKGBUILD, debian changelog).
- [CONTROL_CENTER.md](CONTROL_CENTER.md): `edge` in parity matrix.
- Test update: `public_dict` expects `token_set`.

### Security review follow-ups (included)

- SSH option-injection hardening.
- Pair MITM: pin required before token write.
- Device token out of argv / process listings.
- Telegram: nested `detail`; L3 two-step confirm.

---

## Day-0 fleet sketch (updated)

On each VPS (once):

```bash
cd /path/to/SysSpectogram
.venv/bin/python -m sysspectogram home pair-remote --label laptop
```

On the admin PC (preferred — wizard or CLI):

```bash
# Optional: capture host key first
.venv/bin/python -m sysspectogram fleet keyscan --ssh user@vps

.venv/bin/python -m sysspectogram fleet pair-start \
  --ssh user@vps --home /path/to/SysSpectogram --label laptop \
  --host-key-line '…from keyscan…'

.venv/bin/python -m sysspectogram fleet pair-finish \
  --ssh user@vps --home /path/to/SysSpectogram \
  --code PAIRCODE --id web1 --label "Web 1" \
  --host-key-line '…same…'

.venv/bin/python -m sysspectogram fleet status --scope all
.venv/bin/python -m sysspectogram home seed-never-ban   # on each VPS before soft+
```

Mass ops (explicit):

```bash
.venv/bin/python -m sysspectogram fleet attack --scope all --level L2 --yes
.venv/bin/python -m sysspectogram fleet ban --ip 203.0.113.10 --scope all --yes
.venv/bin/python -m sysspectogram edge under-attack --yes   # if CF configured
```

---

## Fixes in this release (CI / docs)

- Document `edge` in the CLI parity matrix ([CONTROL_CENTER.md](CONTROL_CENTER.md))
- Fleet `public_dict()` test expects `token_set`, not masked `device_token` string

---

## Breaking / migration notes

- Scripts and mass ops that called `fleet attack` / `ban` / `release` / `unlock-locked` / `profile-apply` **without** `--yes` from non-TTY will exit `2` with `need --yes`
- Mutating fleet SSH without `host_key_line` fails unless `FLEET_SSH_TOFU=1`
- `fleet pair-finish` requires a pin (or TOFU) before writing the token
- UI list/graph JSON no longer includes `device_token: "***"` — use `token_set`

---

## Non-goals (still)

- No own DDoS scrubber / BGP / anycast
- No auto Cloudflare Under Attack without confirm
- No public control HTTPS API
- No Win/mac as *guarded* hosts (hub manages remote Linux VPS only)
- No unlock codes in Telegram
- No silent never-ban writes from alerts / auto-policy

---

## GitHub Release body (short paste)

```text
SysSpectogram v1.2.2 — Fleet hub hardening, Edge CDN, Fleet Center

Follow-up to v1.2.1. Safer multi-VPS admin hub: confirm gates, SSH token
on stdin, host-key pinning, soft IP fan-out, Edge/Cloudflare under_attack
(playbook M), never-ban seed helpers, Control Center pair wizard + fleet
hub only, thin Fleet Center app, Fleet Telegram allowlist + L3 confirm.

Do not use v1.2.0 (broken install). Prefer this tag; same-version rule
for GUI + wheel + agent. Full notes: docs/RELEASE_v1.2.2.md

Install (headless):
  curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.2/scripts/friend-day0.sh | bash -s -- v1.2.2
```
