# Fleet CLI (brief)

Admin-PC multi-VPS registry. Store: `~/.config/sysspectogram/fleet.json` (0600).  
Tokens are redacted in `fleet list` / `fleet graph` (`token_set` only). Never paste `device_token` into Telegram.

Prefix every command with `python -m sysspectogram` (or `.venv/bin/python -m sysspectogram`).

## Registry

| Command | Purpose |
|---------|---------|
| `fleet path` | Print default `fleet.json` path |
| `fleet list` | Hosts (tokens redacted) |
| `fleet graph` | Hosts + groups + profiles + edges + dependents |
| `fleet add --id … --ssh user@host [--home …] [--device-id …] [--device-token …] [--role worker\|primary\|…]` | Upsert host |
| `fleet pin-host --id … --host-key-line '…'` | Pin SSH host key (needed for mutating ops) |
| `fleet primary --id …` | Mark primary |
| `fleet remove --id …` | Remove host |

## Ops (scope = `all` \| host id \| `group:id`)

| Command | Purpose |
|---------|---------|
| `fleet status --scope …` | SSH status fan-out |
| `fleet unlock-locked --scope … [--yes]` | Unlock LOCKED hosts (codes stay on admin PC) |
| `fleet attack --scope … --level L2\|L3 [--deps] [--yes]` | Quarantine (L2) / lockdown (L3) |
| `fleet release --scope … [--yes]` | Clear quarantine / lockdown |
| `fleet ban --scope … --ip … [--ttl 3600] [--yes]` | Soft IP ban on every eligible host |
| `fleet incidents --scope … [--limit 40]` | Merged incidents/alerts feed |
| `fleet mark-fp --scope … [--label host_fp]` | Record host ML false positive |
| `fleet warmup --scope local\|all\|…` | Shield readiness checklist |

Destructive ops require `--yes` when stdin is not a TTY (Fleet Hub always passes `--yes` after UI confirm).

## Profiles / groups / graph edges

```bash
fleet profile-set --id web-soft --label "Web soft" --settings '{"response.mode":"observe"}'
fleet profile-apply --id web-soft --scope group:prod --yes
fleet group-set --id prod --label Production --hosts web1,web2 --profile-id web-soft
fleet edge-add --from web1 --to worker1 --kind depends_on
fleet edge-rm --from web1 --to worker1
```

## Pairing (home)

```bash
# On VPS (~5 min code; do not send via Telegram)
home pair-remote --label laptop

# On admin PC over SSH
home pair-complete PAIRCODE --label laptop   # prints device_token once

home remote-list
home remote-revoke --device-id … | --all
```

Then `fleet add … --device-token …`.

## Edge / CDN (hub)

Not a scrubber — Cloudflare Under Attack + playbook M. See [EDGE.md](EDGE.md).

```bash
edge status [--lang en|ru]
edge under-attack --yes
edge clear [--level high] --yes
edge playbook [--lang en|ru] [--json]
```

## Fleet Telegram

```bash
export FLEET_TELEGRAM_BOT_TOKEN=…
export FLEET_TELEGRAM_CHAT_ID=…
fleet tg
```

More context: [FLEET.md](FLEET.md).
