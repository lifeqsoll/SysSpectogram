# Unexpected root watch

Detect **new uid=0 processes** after a learn window and alert via Telegram (Kill / Lockdown).

## Where it runs

| Mode | Path | When |
| --- | --- | --- |
| **Preferred** | Rust agent `ProcWatcher` | `agent.enabled: true` and `agent.root_watch: true` (default) |
| Fallback | Python `sysspectogram.root_watch` | Whenever root-watch is configured and the agent is **not alive** (missing binary, crash, or `agent.enabled: false`) |

The Python poller starts whenever root-watch is wanted. Each cycle skips work while `_running_agent_pid` sees a live agent; otherwise it polls and may emit `root_watch_fallback_active` once.

Processes shorter than one poll interval can be missed on the Python path. Prefer `poll_sec: 10` for fallback (default when the agent is enabled).

## Soft-allow

Processes with an executable are soft-allowed only by **exact canonical exe path**. Comm prefixes apply only to kernel threads (no exe). Paths under `/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`, `/home`, `/root`, `memfd:`, and `(deleted)` are never soft-allowed.

## Agent behavior

1. For `root_learn_sec` (default 300) record root identities `(pid, starttime, exe)` and persist them to a root-only baseline file tagged with `boot_id`.
2. On respawn, a fresh baseline for this boot skips the learn window; a missing/stale file learns again.
3. Skip kernel threads (no `/proc/pid/exe`).
4. Soft-allow exact system exes; pass extras with `--root-allow` (`/path` exact, or bare name + system-dir exe).
5. Skip processes in the trusted tree (guard / agent / phoenix pidfiles + descendants).
6. cron/systemd-timer children may be `medium`; unknown `/tmp` binaries stay `critical`.
7. Emit `agent_unexpected_root` (HMAC required).

CLI:

```bash
sysspectogram-agent --root-watch --root-learn-sec 300 \
  --root-allow /usr/local/bin/mytool --root-allow customd
# disable:
sysspectogram-agent --no-root-watch
```

## Guard / Telegram

Guard maps `agent_unexpected_root` to the root alert UI (Kill process, Lockdown, Ignore proc).

**Honest limit:** you cannot “remove root” without ending the process. Kill needs privileges; Isolate locks network. Same-host root can still stop services; eBPF kill witness needs a binary built with the `ebpf` feature (release musl builds are userspace-only).

## Config

```yaml
agent:
  root_watch: true
  root_learn_sec: 300

root_watch:
  enabled: false   # set true if you want Python-only without agent
  learn_sec: 300
  poll_sec: 10     # recommended for Python fallback
  allow_comms: []
```

See [AGENT.md](AGENT.md), [AGENT_PROTECT.md](AGENT_PROTECT.md), [EBPF_SETUP.md](EBPF_SETUP.md).
