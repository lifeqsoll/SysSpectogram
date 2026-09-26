# Agent self-protect (anti-silence)

Goal: killing the Rust agent is **loud and short** - not silent prelude to a rootkit.
We do **not** claim unkillable under a hostile kernel.

## Layers

| Layer | Behavior |
| --- | --- |
| systemd | `Restart=always`, SIGTERM stop -> CLEAN_SHUTDOWN |
| Phoenix | `--phoenix` spawns `--role watchdog` twin that respawns agent on unexpected death |
| Install check | Warn if binary world-writable / not under `/usr/local/sbin` |
| CLEAN_SHUTDOWN | SIGTERM emits signed `agent_kirk_clean_shutdown`; guard suppresses Dead-man |
| SIGKILL / crash | No clean marker -> watchdog respawn + guard `agent_kirk_agent_down` |
| UDS auth | mode 0600 + same-UID PEERCRED (fail-closed) + HMAC-SHA256 for Kirk CRITICAL |
| auto_isolate | requires valid HMAC (`hmac_ok`) and `kirk.allow_ssh_cidrs` |

Shared secret: `state/agent_hmac.secret` (or `SYSSPECTOGRAM_AGENT_HMAC`). Guard creates it; agent must use the same path (`--hmac-secret`).

**Same-UID model (honest):** HMAC alone does not stop a process that already shares the UID and can read the secret. Mitigation is **PEERCRED PID allowlist** refreshed from `state/agent.pid` + `state/watchdog.pid`: only those PIDs may send on the UDS. Other same-UID processes with a stolen secret are rejected.

**Anti-swap:** guard seals the agent binary (`state/agent_binary.seal.json` path+sha256). Each datagram's peer PID must have `/proc/pid/exe` matching the seal. Replacing the binary on disk (or pointing pidfile at another process) drops the sender and raises `agent_exe_mismatch`.

Residual: root (or whoever can write the sealed path and restart) can still replace the agent; install under root-owned `/usr/local/sbin`.

Unexpected SSH: `sessions.*` watches `who`; after learn window, TG **Kick tty** / **Ban IP**.

Unexpected root: agent `ProcWatcher` emits `agent_unexpected_root` after learn — see [ROOT_WATCH.md](ROOT_WATCH.md). Python `root_watch` is fallback only when the agent is off.

## Install

```bash
sudo install -m 0755 -o root -g root \
  agent/target/release/sysspectogram-agent /usr/local/sbin/sysspectogram-agent
sudo install -m 0644 packaging/sysspectogram-agent.service \
  /etc/systemd/system/sysspectogram-agent.service
sudo mkdir -p /run/sysspectogram /opt/sysspectogram/state
sudo systemctl daemon-reload
sudo systemctl enable --now sysspectogram-agent
```

Do **not** rely on `chattr +i` (breaks updates). Prefer root-owned path above.

## Lab checks

```bash
# intentional stop - must NOT panic / isolate
sudo systemctl stop sysspectogram-agent

# unexpected kill - expect restart + alert
sudo kill -9 $(cat /run/sysspectogram/agent.pid)
```

See [SECURITY.md](../SECURITY.md) and [KIRK.md](KIRK.md).
