# Telegram control plane

[English](TELEGRAM.md) · [Русский](TELEGRAM_RU.md)

SysSpectogram `guard --telegram` exposes a phone remote for status, audit, OSINT, sims, and confirmed response actions. Only `TELEGRAM_CHAT_ID` is accepted.

## Console unlock (v0.4)

If someone steals `.env` (bot token + chat id), they still should not drive **kill/ban/lockdown** without the host. After `guard --telegram` starts:

1. Host console prints a **6-digit TELEGRAM UNLOCK CODE** (never sent in the TG message body).
2. Bot tells the allowlisted chat that the control plane is **LOCKED**.
3. You send `/unlock 123456` from that chat.
4. Session stays open for `telegram.unlock_ttl_sec` (default **2h**). `/lock` regenerates a new code on the console.

Also gated: live web / Mini App SOAR actions (`/api/action`) use the same unlock session. Unlock via TG `/unlock` **or** Mini App Settings → unlock code (`POST /api/unlock`). While LOCKED, process lists and ban details are hidden from the dashboard snapshot.

**Brute-force:** after 5 bad codes the console prints a **new** code; after 8 failures in 5 minutes unlock is refused until you wait / restart.

```yaml
# configs/default.yaml
telegram:
  require_console_unlock: true
  unlock_ttl_sec: 7200
```

## Setup

```bash
# .env (gitignored)
TELEGRAM_BOT_TOKEN=123:ABC
TELEGRAM_CHAT_ID=6360...

python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

`--dry-run`: ban/kill/shield print what would happen; no nft/SIGKILL.

## Slash commands

### Status & help
| Command | Maps to / notes |
| --- | --- |
| `/ping` | liveness (+ LOCKED/unlocked) |
| `/unlock <code>` | console pairing unlock |
| `/lock` | re-lock; new code on host console |
| `/help` `/start` | full command list + menu |
| `/menu` | inline shortcuts |
| `/version` | package version, model path, dry_run |
| `/status` | uptime, quiet/lockdown, listens, allowlist |
| `/digest` | alert counts by rule |
| `/last [n]` | last perimeter alerts |
| `/recipes` | best CLI flag recipes |

### Host audit (CLI `audit`)
| Command | Equivalent |
| --- | --- |
| `/audit` | formatted audit report |
| `/processes` | `audit processes` |
| `/ports` | `audit ports` |
| `/rootkit` | `audit rootkit` |
| `/panel` | live dual heatmap (metrics + top-PID CPU) |
| `/score` | ~65s collect + ensemble score + panel |

### Perimeter / response
| Command | Notes |
| --- | --- |
| `/recon <ip>` | OSINT + nmap -F |
| `/labnmap <ip>` | allowlisted lab nmap only |
| `/ban <ip> [ttl\|perm]` | confirm → nft |
| `/unban <ip>` | confirm |
| `/kill <pid>` | confirm |
| `/allow <ip>` | allowlist |
| `/mute <ip> [sec]` | silence alerts |
| `/quiet on\|off` | quiet hours |
| `/lockdown` | double confirm |
| `/bans` | list + Unban buttons |
| `/report` | send JSONL report file |

### Sims / collect / analyze
| Command | Notes |
| --- | --- |
| `/simulate cpu\|mem\|disk\|net\|gpu [dur]` | confirm; max 120s; local only |
| `/collect [dur]` | confirm; max 180s → `reports/tg_collect.csv` |
| `/analyze <csv>` | offline analyze with guard `--model` |

### Terminal-only (shown in `/help`)
`train`, `build-dataset`, `monitor`, `guard`, `watch-perimeter` — too long for chat; use host shell + `/recipes`.

## Inline on alerts

Ban TTL / Allowlist / Mute / Recon / Shield / Kill / Ignore / Report / Lockdown.  
Destructive actions require YES/NO (tokens HMAC, single-use, TTL).

## Safety

- Chat allowlist only  
- No remote shell  
- No auto-ban/kill without button  
- Sims localhost / local resources only  
- AppImage soft-findings filtered in `/audit`

## Live web / Mini App

HTTPS tunnel + `WEBAPP_URL` + `guard --web` → `/dashboard`. Step-by-step: [WEBAPP.md](WEBAPP.md).

## Related

- [CLI recipes](RECIPES.md) · [Рецепты](RECIPES_RU.md)
- [Config](CONFIG.md)
- [Live web / Mini App](WEBAPP.md)
