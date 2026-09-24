# Telegram control plane

[English](TELEGRAM.md) · [Русский](TELEGRAM_RU.md)

SysSpectogram `guard --telegram` exposes a phone remote for status, audit, OSINT, sims, and confirmed response actions. Only `TELEGRAM_CHAT_ID` is accepted.

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
| `/ping` | liveness |
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
