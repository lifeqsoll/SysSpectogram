# Host soft-mitigation (not anti-DDoS)

SysSpectogram can **reduce noise on the VPS itself** (SSH brute, scanners, SYN bursts).
It does **not** replace Cloudflare, scrubbing centers, or ISP upstream DDoS protection.

## What exists

| Signal | Action (when mode ≠ observe) |
| --- | --- |
| `bruteforce_ssh` | auto-ban IP (shield+) |
| `flow_syn_burst` | per-IP + top offender; auto-ban if IP present (shield+) |
| `flow_port_scan` | auto-ban scanner IP (shield+) |
| Menu **Under-scan** | nft lockdown (SYN drop) with **never-ban allow**, optional SYN rate-limit |

Defaults: `response.mode: observe` — alerts only, no ban.

## Safety

1. Set **never-ban** (your SSH admin IP) before soft/full/isolate or Under-scan.
2. Lockdown **refuses** empty allow list (would drop new SSH SYN).
3. Volumetric floods that saturate the NIC/uplink cannot be fixed in userspace nft alone — use the provider / CDN. Hub: [EDGE.md](EDGE.md) (`edge under-attack`).

## Integrity (rootkit track)

See [KIRK.md](KIRK.md), [ROOT_WATCH.md](ROOT_WATCH.md), TG `/rootkit`.
Kirk hide/drift/IMA and FIM changes use **confirm streaks** before Telegram / auto-isolate to cut one-shot noise.
Claims stay **best-effort** on a single host — not rootkit-proof.
