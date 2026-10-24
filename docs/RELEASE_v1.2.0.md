# SysSpectogram v1.2.0 — Fleet + unlock persist + TG charts

Follow-up to [v1.1.1](RELEASE_v1.1.1.md): multi-VPS fleet from one admin PC, lasting unlock sessions, Telegram charts, Attack L2 quarantine / L3 lockdown.

## Download

From the [v1.2.0 GitHub Release](https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.2.0):

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.2.0_amd64.AppImage` / `.deb` | Desktop Control Center (Fleet tab) |
| `sysspectogram-1.2.0-*.whl` + musl agent | Stack (Install stack / day-0) |
| `sysspectogram-helper-x86_64-linux` (+ sha256/minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless one-liners |
| `sysspectogram-helper-packaging.tgz` | Unit + polkit for helper install |

Same-version rule (ADR 0005): GUI, wheel, and agent must match this tag.

## Headless VPS

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/friend-day0.sh | bash -s -- v1.2.0
loginctl enable-linger $USER
```

Optional helper:

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/install-helper-from-release.sh | sudo bash -s -- v1.2.0
```

## Notable changes since v1.1.1

### Fleet (multi-VPS)

- `fleet.json` on the admin PC: hosts, primary, groups, profiles, dependency edges
- Pair flow: `home pair-remote` → SSH `home pair-complete` → device token (no public HTTPS control)
- CLI: `fleet list|graph|status|unlock-locked|attack|release|profile-*|edge-*|warmup|tg`
- Attack **L2** = quarantine ports 80/443; **L3** = lockdown; `--deps` follows graph (skips bastion/dns)
- Control Center **Fleet** tab: table, graph, warmup, apply profile, Attack/Release
- Optional fleet Telegram hub bot (`FLEET_TELEGRAM_*`); per-VPS bots stay for single-host ops
- Docs: [FLEET.md](FLEET.md)

### Unlock & control

- Alphanumeric unlock codes (~5 min TTL); session can persist via `state/control.unlocked` until `/lock`
- No morning re-unlock; no emergency pocket codes; no unlock/pair codes in Telegram
- LOCKED playbook (EN/RU) when Attack/Kill need unlock
- Mass unlock: `fleet unlock-locked` (reads `unlock.code` over SSH on admin PC only)

### Telegram & response

- `/charts` — cpu / mem / net / gpu / disk images
- Auto-kill only when auto-ban/shield path is on (not alone)
- Soft isolate stays IP ban after warmup; L2/L3 stay manual Attack

### Protect / security

- Protect unit resolves venv via `absolute()` (not `resolve()` through symlinks)
- Control socket device-token gate after pair; SSRF/hardening from prior patch line retained

## Docs

[FLEET.md](FLEET.md) · [FRIEND.md](FRIEND.md) · [HOME.md](HOME.md) · [TELEGRAM.md](TELEGRAM.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md) · [SECURITY.md](../SECURITY.md)
