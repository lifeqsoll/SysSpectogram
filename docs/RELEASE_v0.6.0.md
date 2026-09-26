# SysSpectogram v0.6.0 — Harden the agent path

Release after v0.5 Adopt/Kirk: make the **same-UID / lite VPS** path honest and usable —
auth, self-protect, unexpected root in Rust, Role Lab packs, operator feedback.

## Why it matters

| Before (v0.5) | Now (v0.6) |
| --- | --- |
| Critical kirk alerts forgeable on same UDS | **HMAC** + PEERCRED fail-closed + **PID allowlist** + **exe seal** |
| Agent death can go quiet | **Phoenix** watchdog, CLEAN_SHUTDOWN, Dead-man, TG bypass |
| Root process watch = Python `/proc` (heavy on lite) | **Rust ProcWatcher** same walk → `agent_unexpected_root` + TG Kill |
| Unexpected SSH soft | Learn window → **Kick tty** / Ban IP |
| Packs unsigned locally | HMAC **`.sig`** + `validate-pack` |
| Retrain feedback vague | TG **Ignore / As normal / As anomaly** → learner (+ retrain CLI) |
| Role baselines hard without VMs | **Role Lab** collect/train/pack on a PC |

**Honest limits:** cannot revoke uid=0 without Kill; root can still replace a poorly installed binary — install under root-owned `/usr/local/sbin`. Cloud IMA/SB often absent → trust stays `best-effort`.

## What's new

### Agent auth and seal

- HMAC-SHA256 for critical rules (`state/agent_hmac.secret`)
- Same-UID PEERCRED fail-closed; refresh allowlist from agent + watchdog PIDs
- Binary seal (`state/agent_binary.seal.json`); mismatch → loud alert

Docs: [AGENT_PROTECT.md](AGENT_PROTECT.md) · [SECURITY.md](../SECURITY.md)

### Unexpected root (lite-safe)

- `agent.root_watch: true` (default) — detection in agent, no second `/proc` walk
- Python `root_watch` only if `agent.enabled: false`
- Rule: `agent_unexpected_root` (HMAC required)

Docs: [ROOT_WATCH.md](ROOT_WATCH.md)

### Sessions, Role Lab, feedback, OSINT

- [ROLE_LAB.md](ROLE_LAB.md) · [FEEDBACK.md](FEEDBACK.md) · [OSINT.md](OSINT.md) · [DAY0_VPS.md](DAY0_VPS.md)

### CI / packaging

- GitHub Actions pytest + agent checks; release-assets workflow
- `packaging/sysspectogram-agent.service`

## Quick start

```bash
pip install -e ".[dev]"
cd agent && cargo build --release && cd ..
python -m sysspectogram kirk trust
python -m sysspectogram guard --telegram --dry-run
# console unlock code → TG /unlock NNNNNN
```

Agent (root, optional eBPF):

```bash
sudo install -m 0755 -o root -g root \
  agent/target/release/sysspectogram-agent /usr/local/sbin/sysspectogram-agent
sudo /usr/local/sbin/sysspectogram-agent --mode ebpf --phoenix \
  --socket /run/sysspectogram/agent.sock \
  --hmac-secret /opt/sysspectogram/state/agent_hmac.secret
```

## Config knobs (new / important)

```yaml
agent:
  enabled: true
  require_hmac: true
  require_same_uid: true
  root_watch: true
  root_learn_sec: 300
root_watch:
  enabled: false   # Python fallback only without agent
sessions:
  enabled: true
  learn_sec: 120
```

## Docs

- [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md) — forward plan (v0.7+)
- [AGENT.md](AGENT.md) · [KIRK.md](KIRK.md) · [TRUST.md](TRUST.md)
- [RELEASE_v0.5.0.md](RELEASE_v0.5.0.md) — prior Adopt/Kirk release

## Upgrade notes

1. Rebuild agent (`cargo build --release`) — root watch + HMAC live in the binary.
2. Ensure `state/agent_hmac.secret` shared by guard and agent.
3. Prefer systemd unit under `/usr/local/sbin` ([AGENT_PROTECT.md](AGENT_PROTECT.md)).
4. Keep `kirk.auto_isolate: false` until `allow_ssh_cidrs` is set.
