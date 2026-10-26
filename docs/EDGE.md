# Edge / CDN (not anti-DDoS scrubber)

SysSpectogram soft-ban and Under-scan cut noise **on the VPS**. They do **not** stop volumetric L3/L4 floods or huge L7 botnets — those fill the uplink before nft.

**Edge** is a thin hub adapter: call your CDN/WAF (Cloudflare first) or follow playbook M.

## Setup

1. Put the zone behind Cloudflare (orange cloud).
2. Create an API token with **Zone → Zone Settings → Edit** (scope to one zone).
3. In hub `.env`:

```bash
CLOUDFLARE_API_TOKEN=…
CLOUDFLARE_ZONE_ID=…
```

4. Check: `python -m sysspectogram edge status`

## Commands

| Command | Effect |
|---------|--------|
| `edge status` | Linked? current `security_level` + playbook text |
| `edge under-attack --yes` | Set `security_level=under_attack` |
| `edge clear --yes` | Restore (default `high`) |
| `edge playbook [--lang ru]` | Print playbook M |

Never auto-enables Under Attack — always `--yes` or UI confirm.

## Playbook M (gist)

1. Soft fleet IP ban will not save a saturated pipe.
2. If CF linked → Under Attack.
3. Else → provider ticket / blackhole / DNS cut; optional Attack L2 on the **victim** host only.
4. After the wave → `edge clear`.

See also [HOST_MITIGATION.md](HOST_MITIGATION.md), [FLEET.md](FLEET.md).
