# Fleet hub smoke checklist

Run from the admin PC after the user venv has the SysSpectogram wheel (see [docs/FLEET_HUB.md](../docs/FLEET_HUB.md)).

```bash
# 0) env (optional)
# export SYSSPECTOGRAM_HOME=/path/to/checkout-or-hub
# export SYSSPECTOGRAM_FLEET_PATH=…   # only if overriding default fleet.json

# 1) where fleet.json will live
python -m sysspectogram fleet path

# 2) register a host (fill real values; device_token once from pair-complete)
python -m sysspectogram fleet add \
  --id web1 --label "Web 1" --ssh user@vps.example \
  --home /path/on/vps/SysSpectogram \
  --device-id DEVICE_ID --device-token DEVICE_TOKEN \
  --role primary

# 3) pin OpenSSH host key (required for mutating ops)
python -m sysspectogram fleet pin-host \
  --id web1 \
  --host-key-line 'ssh-ed25519 AAAA…'

# 4) SSH status fan-out
python -m sysspectogram fleet status --scope all

# 5) warmup checklist (local hub, or remote with --scope all|web1)
python -m sysspectogram fleet warmup --scope local
# python -m sysspectogram fleet warmup --scope all

# 6) edge / Cloudflare adapter (hub .env CLOUDFLARE_* — see docs/EDGE.md)
python -m sysspectogram edge status
```

Expect JSON with `"ok": true` (or a clear missing-config message for edge). Mutating ops (`attack`, `release`, …) need `--yes` when not on a TTY.
