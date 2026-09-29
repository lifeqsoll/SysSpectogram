# Trust and privacy

SysSpectogram does **not** phone home. No mandatory telemetry.

- Alerts go only to **your** Telegram bot / webhook / local JSONL.
- OSINT lookups are local-cache first; DNSBL/Tor fetch is opt-in / background.
- Profile packs from third parties affect FP/FN; verify SHA-256 and minisign
  signatures before production use ([SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)).
- Model loading can enforce a signed deterministic manifest before Torch,
  joblib, or ONNX deserialization. Existing configs remain compatible until
  `supply_chain.enforce: true` is selected.
- Default `response.mode: observe` does not auto-ban.
- Agent critical path: HMAC + same-UID PEERCRED + PID allowlist + exe seal ([AGENT_PROTECT.md](AGENT_PROTECT.md)).

Update path:

```bash
cd /opt/sysspectogram
sudo git fetch --tags && sudo git checkout v0.8.0
source .venv/bin/activate
pip install -e ".[dev]"
cd agent && cargo build --release && cd ..
# optional: ROLE=nginx bash scripts/bootstrap.sh
sudo systemctl restart sysspectogram-guard.service
sudo systemctl restart sysspectogram-agent.service
```

See [DAY0_VPS.md](DAY0_VPS.md), [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [RELEASE_v0.8.0.md](RELEASE_v0.8.0.md), [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md).
