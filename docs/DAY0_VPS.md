# Day-0 — first VPS install

Goal: useful observe-mode defense on a small Linux VPS in about **15 minutes**, without PyTorch.

## 1. Install

```bash
git clone https://github.com/lifeqsoll/SysSpectogram.git
cd SysSpectogram
python -m venv .venv && source .venv/bin/activate
pip install -e ".[onnx]"    # or .[dev] for tests/tools
```

## 2. Configure (canonical)

```bash
python -m sysspectogram configure --accept-recommended --role ssh
# interactive instead:
# python -m sysspectogram configure --role ssh
```

This writes `configs/default.yaml` defaults: `runtime` without Torch when possible, `response.mode: observe`, FIM on for lite, Telegram prompts if desired.

## 3. Model (optional on day-0)

- **No model yet:** run perimeter + agent (`notorch`).
- **Have ONNX pack:** put under `artifacts/live`, set `runtime.prefer: onnx`, verify:

```bash
python -m sysspectogram supply-chain verify artifacts/live
python -m sysspectogram guard --model artifacts/live --telegram --dry-run
```

Builder → VPS flow: [TRAIN_BRIDGE.md](TRAIN_BRIDGE.md), [SUPPLY_CHAIN_STORY.md](SUPPLY_CHAIN_STORY.md).

## 4. Agent

```bash
cd agent && cargo build --release && cd ..
sudo install -m 0755 -o root -g root \
  agent/target/release/sysspectogram-agent /usr/local/sbin/sysspectogram-agent
```

Prefer `agent.auto_start` from guard (phoenix on by default). Manual systemd: [AGENT_PROTECT.md](AGENT_PROTECT.md).

## 5. Run observe

```bash
python -m sysspectogram kirk trust
python -m sysspectogram guard --telegram --dry-run
# console prints unlock code → Telegram /unlock NNNNNN
```

## Checklist

- [ ] `/labels` shows seeded role rules
- [ ] FIM enabled (`agent.fim.enabled`)
- [ ] Alerts writing (`alerts.sinks` file path)
- [ ] `kirk.auto_isolate` still **false** until CIDRs set
- [ ] Unlock works; SOAR stays locked until `/unlock`

## Harden later

- `response.mode: shield` + `kirk.allow_ssh_cidrs: ["YOUR.IP/32"]`
- Remote sink (HTTPS/syslog) — [CONFIG.md](CONFIG.md)
- `supply_chain.enforce: true` after public key installed
- Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)

Cold / air-gapped notes: [COLD_INSTALL.md](COLD_INSTALL.md).
