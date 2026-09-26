# Day-0 - first VPS install (v0.6+)

Goal: useful defense on a **1 vCPU / 1GB** box in under 30 minutes, **without PyTorch**.

## 1. Install

```bash
git clone https://github.com/lifeqsoll/SysSpectogram.git
cd SysSpectogram
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # add .[onnx] if you have cnn.onnx
```

## 2. Config

```bash
python -m sysspectogram setup    # Telegram .env
# configs/default.yaml: runtime: notorch, response.mode: observe
# agent.root_watch: true (unexpected root via Rust agent)
```

## 3. Run (observe)

```bash
python -m sysspectogram kirk trust
python -m sysspectogram guard --telegram --dry-run
# console shows unlock code; TG /unlock NNNNNN
```

## 4. Agent (recommended)

```bash
cd agent && cargo build --release && cd ..
sudo install -m 0755 -o root -g root \
  agent/target/release/sysspectogram-agent /usr/local/sbin/sysspectogram-agent
# auto_start from guard, or systemd — see AGENT_PROTECT.md
sudo -E /usr/local/sbin/sysspectogram-agent --mode ebpf --phoenix \
  --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock" \
  --hmac-secret state/agent_hmac.secret
```

HMAC secret is created by guard under `state/agent_hmac.secret`. Share the same path with the agent.

## 5. Harden when ready

- Set `response.mode: shield` and `kirk.allow_ssh_cidrs: ["YOUR.IP/32"]`
- Keep `kirk.auto_isolate: false` until you understand alerts
- Pull a profile pack or train with `role-lab` on a PC ([ROLE_LAB.md](ROLE_LAB.md))
- Use TG feedback buttons to tune FP ([FEEDBACK.md](FEEDBACK.md))

## Docs

[KIRK.md](KIRK.md) | [AGENT_PROTECT.md](AGENT_PROTECT.md) | [ROOT_WATCH.md](ROOT_WATCH.md) | [TRAIN_BRIDGE.md](TRAIN_BRIDGE.md) | [OSINT.md](OSINT.md) | [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md)
