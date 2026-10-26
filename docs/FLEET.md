# Fleet: many VPS from one admin PC (+ fleet Telegram)

Manage **multiple** SysSpectogram hosts from a laptop (Control Center **Fleet** tab + CLI) and an optional **fleet Telegram bot**. Each VPS still has its own bot for single-host ops.

**Admin hub setup** (OpenSSH Client, user venv, no helper/polkit on the laptop): [FLEET_HUB.md](FLEET_HUB.md). Smoke checklist: [scripts/fleet-hub-smoke.md](../scripts/fleet-hub-smoke.md).

Security model: **SSH + pair code (~5 min) + device token**. No public HTTPS control API. No unlock/pair codes in Telegram. No “emergency pocket codes”.

Full design notes: [superpowers/plans/2026-10-24-remote-cc-ssh.md](superpowers/plans/2026-10-24-remote-cc-ssh.md).

---

## Concepts

| Piece | Where | Role |
|-------|--------|------|
| Per-VPS bot | Each server `.env` | Status, charts, kill, `/unlock` for **that** host |
| Fleet bot | Admin hub `FLEET_TELEGRAM_*` | Pick host / ALL → status, unlock-locked, Attack L2/L3, Release |
| Control Center Fleet | Admin PC | Same ops + host table |
| `fleet.json` | `~/.config/sysspectogram/fleet.json` (0600) | Hosts, primary, groups, profiles, edges, tokens |
| Device token | Issued once at pair | Required on control.sock once any device is paired |

**Unlock:** after `/unlock`, session stays open until `/lock` (and can persist across guard restart via `state/control.unlocked`). You do **not** unlock every morning. Mass unlock: CC / `fleet unlock-locked` (reads `unlock.code` over SSH on the admin PC only).

**If a host is LOCKED** during Attack/Kill: you get a full playbook (EN/RU) — use that host’s bot, or Fleet → Unlock locked, or SSH `cat state/unlock.code`.

---

## Day-0: pair one VPS into the fleet

On the **VPS**:

```bash
cd /path/to/SysSpectogram
.venv/bin/python -m sysspectogram home pair-remote --label laptop
# shows pair_code — do not send via Telegram
```

On the **admin PC** (within ~5 minutes), via SSH:

```bash
ssh user@vps 'cd /path/to/SysSpectogram && .venv/bin/python -m sysspectogram home pair-complete PAIRCODE --label laptop'
# save device_token from JSON (shown once)
```

Register in fleet:

```bash
.venv/bin/python -m sysspectogram fleet add \
  --id web1 --label "Web 1" --ssh user@vps \
  --home /path/to/SysSpectogram \
  --device-id … --device-token … \
  --role primary   # or worker / canary / bastion / dns
```

Pin the SSH host key (recommended). Put a full `known_hosts` line into `fleet.json` as `host_key_line` for that host (or `keytype base64` — the CLI will prefix the hostname). When set, fleet SSH uses `StrictHostKeyChecking=yes` against a temp known_hosts file instead of `accept-new`.

Mark primary (optional):

```bash
.venv/bin/python -m sysspectogram fleet primary --id web1
.venv/bin/python -m sysspectogram fleet list
```

Revoke a laptop on the VPS: `home remote-list` / `home remote-revoke --device-id …` or `--all`.

---

## Isolation levels (Attack)

| Level | Effect on public website on that IP | Command |
|-------|--------------------------------------|---------|
| **L2** (default) | New traffic to **80/443** (configurable ports) dropped; SSH OK; egress OK | `fleet attack --scope web1 --level L2` |
| **L3** | Full inbound SYN lockdown (needs never-ban); site down for new clients | `fleet attack --scope web1 --level L3` |
| **Release** | Remove quarantine / lockdown tags (+ kirk_release best-effort) | `fleet release --scope web1` |

Alerts alone never cascade. Soft auto-ban (shield) stays **IP bans** after warmup — not L2/L3.

---

## Profiles, groups, graph

Profiles push allowlisted `home settings` keys (never `response.mode=isolate` — use Attack for that).

```bash
fleet profile-set --id web-soft --label "Web soft" \
  --settings '{"response.mode":"observe","response.never_ban_cidrs":"10.0.0.0/8"}'
fleet profile-apply --id web-soft --scope group:prod

fleet group-set --id prod --label Production --hosts web1,web2 --profile-id web-soft

fleet edge-add --from web1 --to worker1 --kind depends_on --note "API → workers"
fleet edge-rm --from web1 --to worker1
fleet graph                                   # hosts + edges + one-hop dependents

fleet attack --scope web1 --level L2 --deps  # also touch graph dependents (skips bastion/dns)

fleet incidents --scope all --limit 40       # merged alerts/incidents feed
fleet mark-fp --scope web1                   # record host ML false positive on hosts
fleet ban --scope all --ip 203.0.113.66      # ban IP on every host in scope
```

## Warmup (before shield)

Local checklist on a VPS (or admin PC `fleet warmup --scope local`):

```bash
home warmup                    # never_ban, labels≥3, unlock session, …
fleet warmup --scope all       # same over SSH for fleet hosts
```

Enable soft shield only when `ready_for_shield` is true. Attack L2/L3 stays manual.

---

## CLI cheat sheet (admin PC)

```bash
fleet path
fleet list
fleet graph
fleet status --scope all
fleet unlock-locked --scope all
fleet attack --scope web1 --level L2
fleet attack --scope web1 --level L2 --deps
fleet attack --scope all --level L3
fleet release --scope all
fleet profile-set / profile-apply
fleet group-set / edge-add / edge-rm
fleet warmup --scope local|all
fleet tg                          # fleet Telegram bot (blocking)
```

Optional: `--identity ~/.ssh/id_ed25519`, `--path /custom/fleet.json`. Scope: `all`, host id, or `group:<id>`.

---

## Fleet Telegram bot

On the hub (admin PC with linger, or a small always-on box):

```bash
export FLEET_TELEGRAM_BOT_TOKEN=…   # separate bot recommended
export FLEET_TELEGRAM_CHAT_ID=…
# Optional: only these Telegram **user** IDs may drive the bot (comma-separated).
# Group/channel IDs are ignored — required for group chats.
export FLEET_TELEGRAM_ALLOW_USERS=123456789,987654321
.venv/bin/python -m sysspectogram fleet tg
```

When `FLEET_TELEGRAM_ALLOW_USERS` is set, only those **user** IDs in the configured chat may drive the bot (callbacks get `unauthorized` otherwise). Group IDs in the list do nothing. If unset, a private DM with `FLEET_TELEGRAM_CHAT_ID` is accepted; a **group** chat always needs the user allowlist.

Hub unlock code is written to `~/.config/sysspectogram/fleet.hub_unlock.code` (0600), **not** to Telegram. `/unlock CODE` once → session until `/lock`.

Then: `/menu` → pick host or ALL → Status / Unlock locked / Attack L2|L3 / Release.

**Incident without Control Center:** use the **per-VPS bot** first; or fleet bot if hub session still unlocked; or SSH to hub and unlock fleet bot with the hub code file.

---

## Control Center

Open **Fleet** in the sidebar: host table, graph edges, profiles, Warmup, scope, Status, Unlock locked, Attack L2/L3 (+ optional deps), Release, Apply profile.

---

## Safety reminders

- After `pair-remote`, control actions need `device_token` (local CC on the VPS should use a paired profile or avoid pairing until you understand this).
- Never auto-isolate bastion/DNS in policies (graph/Attack deps are conservative).
- Soft mitigation ≠ anti-DDoS; put CDN in front of public sites. Hub Edge panel / `edge` CLI — see [EDGE.md](EDGE.md).
- Mutating fleet ops need `host_key_line` (`fleet pin-host`) unless `FLEET_SSH_TOFU=1`.
- Destructive CLI ops need `--yes` when stdin is not a TTY.
- Soft = L1 IP ban; L2 = site ports on that node; plan DNS/canary failover if you need zero downtime.
