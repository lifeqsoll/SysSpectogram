# Unexpected root watch

Detect **new uid=0 processes** after a learn window and alert via Telegram (Kill / Lockdown).

## Where it runs

| Mode | Path | When |
| --- | --- | --- |
| **Preferred** | Rust agent `ProcWatcher` | `agent.enabled: true` and `agent.root_watch: true` (default) |
| Fallback | Python `sysspectogram.root_watch` | Only if agent is **disabled** and `root_watch.enabled: true` |

Lite VPS: keep the agent on. Detection reuses the same `/proc` walk the agent already does — no extra Python poller.

## Agent behavior

1. For `root_learn_sec` (default 300) record all root PIDs (real or effective uid 0).
2. After learn: new root PID not in baseline → alert once.
3. Skip kernel threads (no `/proc/pid/exe`).
4. Soft-allow known daemon `comm` prefixes (systemd, sshd, sysspectogram-agent, …).
5. Emit `agent_unexpected_root` (severity `critical`, HMAC required).

CLI:

```bash
sysspectogram-agent --root-watch --root-learn-sec 300
# disable:
sysspectogram-agent --no-root-watch
```

## Guard / Telegram

Guard maps `agent_unexpected_root` to the root alert UI (Kill process, Lockdown, Ignore proc).

**Honest limit:** you cannot “remove root” without ending the process. Kill needs privileges; Isolate locks network.

## Config

```yaml
agent:
  root_watch: true
  root_learn_sec: 300

# Python poller — leave false when agent is on
root_watch:
  enabled: false
  learn_sec: 300
  poll_sec: 60
  allow_comms: []
```

See [AGENT.md](AGENT.md), [AGENT_PROTECT.md](AGENT_PROTECT.md), design note under `docs/superpowers/specs/`.
