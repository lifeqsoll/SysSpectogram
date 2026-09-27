# Cold install checklist (Track F)

Operator-run on a **clean** Linux VPS. Target: first useful alert under 30 minutes.

## Prerequisites

- Linux x86_64, systemd optional
- Python 3.10+
- Root or sudo for agent/`nft` (guard can run observe/dry-run as user)

## Steps

1. Clone / unpack release; `python -m venv .venv && . .venv/bin/activate && pip install -e '.[onnx]'` (or `.[ml]` on builder).
2. Build agent (optional but recommended): `cd agent && cargo build --release`.
3. Configure:
   ```bash
   python -m sysspectogram configure --accept-recommended --role ssh
   # or interactive: python -m sysspectogram configure --role ssh
   ```
4. Put model under `artifacts/real_v3` (or unpack a role pack).
5. Set Telegram in `.env` if not set during configure:
   `TELEGRAM_BOT_TOKEN=…` `TELEGRAM_CHAT_ID=…`
6. Start:
   ```bash
   python -m sysspectogram guard --model artifacts/real_v3 --telegram
   ```
7. Console: copy **UNLOCK CODE** → TG `/unlock CODE`.
8. `/status` `/digest` `/labels` — confirm agent heartbeat (not `agent_kirk_agent_down`).
9. Label 2–4 false positives with **As normal** (optionally **+ similar**).
10. Optional: `python -m sysspectogram feedback retrain-if --model artifacts/real_v3` if `feedback.if_refit` enabled.

## Pass criteria

- [ ] Guard stays up ≥10 min without crash
- [ ] Agent metrics keep heartbeat green
- [ ] TG unlock works; Kill in dry-run only prints text
- [ ] `/labels` shows seeded role rules after configure
- [ ] Quiet ssh VPS heading toward &lt;10 alerts/day after tuning

## Gaps

File issues for Day-0 friction. Do not force Torch on 1 GB VPS.
