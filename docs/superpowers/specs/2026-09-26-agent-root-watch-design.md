# Agent root watch (Rust) — design

Date: 2026-09-26  
Status: implemented  
Goal: keep unexpected-root detection on lite VPS without a Python `/proc` poller.

## Problem

Python `root_watch` walks `/proc` on a timer. On lite that is redundant load: the Rust agent already walks `/proc` in `ProcWatcher`. Turning the feature off for lite loses coverage; keeping Python on lite fights the resource budget we just optimized for.

## Decision

Move detection into the Rust agent (same `/proc` pass as `ProcWatcher`). Guard keeps Telegram Kill UX. Python `root_watch` becomes fallback only when the agent is disabled.

## Architecture

```
ProcWatcher.poll (/proc walk, already running)
  -> parse Uid from status (same open as Name/PPid)
  -> after learn window: new euid/ruid==0 pid not in baseline
  -> emit AgentAlert rule_id=agent_unexpected_root (critical, HMAC)
  -> Unix socket -> guard on_agent_alert
  -> TG send_root_alert / Kill + Lockdown + Ignore proc
```

## Agent behavior

1. On first bootstrapped poll (or for `learn_sec` after start, default 300s): record all root PIDs into baseline; emit nothing.
2. After learn: for each pid with real or effective uid 0:
   - skip if pid in baseline or already alerted
   - skip kernel threads (no `/proc/pid/exe`)
   - skip soft-allow `comm` prefixes (systemd, sshd, sysspectogram-agent, …) — add to baseline quietly
   - else emit `agent_unexpected_root` once per pid
3. Cost: one extra `Uid:` parse on the status file already read for Name/PPid. No second `/proc` walk.
4. Works in both `userspace` and `ebpf` modes (detection is userspace; no new probe).

## Guard / config

| Knob | Default | Meaning |
|------|---------|---------|
| `agent.enabled` | true | root alerts come from agent |
| `root_watch.enabled` | false | Python poller; only if agent off or explicit dual |
| `root_watch.learn_sec` | 300 | used by agent via CLI/env or mirrored config later |
| Soft allow_comms | same as today | optional agent flag / hardcoded defaults |

When agent is enabled, do **not** start the Python `root_loop` (even if someone flips `root_watch.enabled`). Document: enable Python only with `agent.enabled: false`.

On `agent_unexpected_root`, guard routes to the existing root TG path (`send_root_alert`) so Kill button stays. Critical HMAC required like other signed agent alerts.

## Out of scope

- eBPF setuid/exec hooks (possible later; not required for lite)
- Revoking uid=0 without kill (impossible in-userspace)
- Auto-kill without TG confirm

## Tests

- Rust unit: Uid parse; learn then alert; kernel thread skip; soft allow
- Python: guard maps `agent_unexpected_root` to root alert path (mock)
- Keep `tests/test_root_watch.py` for fallback module

## Success

Lite profile: agent on, Python root_watch off, unexpected root still alerts in TG with Kill. Extra CPU vs current agent poll ≈ negligible (no second walk).
