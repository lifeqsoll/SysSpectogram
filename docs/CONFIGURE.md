# Configure (Day-0 TUI)

Unified terminal setup for SysSpectogram v0.8.

```bash
# Interactive (recommended first run)
python -m sysspectogram configure

# Scripted / cold VPS: apply host_probe recommendations
python -m sysspectogram configure --accept-recommended --role ssh
```

## What it does

1. **host_probe** — RAM, vCPU, container, desktop, onnx/torch → recommends `lite`/`full`, `runtime.prefer`, agent on/off, `userspace` mode, flow, feedback.
2. Shows a table of recommendations with reasons.
3. Changing a value away from the recommendation **requires confirmation** (warns that current settings are best for this machine).
4. Writes `configs/default.yaml` (deep-merge) + `.env` (Telegram / role).
5. Optionally seeds **role FP process labels** (`state/process_labels.json`).
6. Saves `state/host_probe.json`.
7. Offers signed model-manifest enforcement. It stays disabled unless a
   minisign public key is supplied.

## Next steps

```bash
python -m sysspectogram guard --model artifacts/real_v3 --telegram
# console prints UNLOCK CODE → TG /unlock CODE
```

See [COLD_INSTALL.md](COLD_INSTALL.md), [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [FEEDBACK.md](FEEDBACK.md), [DAY0_VPS.md](DAY0_VPS.md).
