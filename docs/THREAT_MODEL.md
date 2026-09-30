# Threat model

Honest scope for SysSpectogram on a single Linux VPS / host. This is **not** a claim of unkillable EDR.

## Assets

| Asset | Why it matters |
| --- | --- |
| Host integrity (binaries, auth files, modules) | Primary detection target |
| Alert evidence (jsonl, remote sinks) | Forensics / paging |
| Model artifacts (`cnn.onnx`, `scaler.json`, `iforest.ssf.npz`) | Integrity of detection |
| Agent UDS + HMAC secret | Authenticity of agent alerts |
| Telegram / web unlock | Authorization for SOAR actions |

## Adversaries

1. **Remote scanner / brute** — noisy perimeter events.
2. **Foothold (non-root)** — suspicious processes, egress, file touches.
3. **Local root on same host** — can stop units, wipe local logs, replace binaries if they control install paths.
4. **Supply-chain tamper** — swapped model pack or release binary before verify.

## Entry points

- `guard` / `monitor` process
- Rust agent Unix socket
- Telegram bot + live web (unlock-gated actions)
- Model / state directories on disk
- Alert sinks (file, syslog, HTTPS)

## Controls

| Control | Mitigates |
| --- | --- |
| Default `response.mode: observe` | Accidental auto-ban |
| Agent HMAC + PEERCRED PID allowlist + exe seal | Forged critical UDS alerts |
| `weights_only` CNN load + pickle-free scaler/IF | Malicious model deserialization |
| Optional `supply_chain.enforce` + minisign | Tampered artifacts |
| FIM baseline + seal | Quiet binary/config swap |
| Phoenix twin + Dead-man + remote sinks | Silent agent kill (makes it louder) |
| `kirk.auto_isolate*` default off + CIDR gate | Self-lockout |
| HTTPS/syslog sinks block private/link-local after DNS resolve | SSRF via hostname / metadata |

## Residual risks (accepted)

- Same-host root can still `systemctl stop`, delete local files, or `rmmod` an optional helper module.
- Advanced kernel malware can lie about `/proc` without out-of-guest visibility (see [VMI.md](VMI.md) for v1.0 ceiling).
- Telegram is a pager, not WORM storage — configure remote sinks for evidence off-box.
- Optional DKMS `sysspectogram_wd` is a PID registry scaffold; many cloud kernels will not load it.

## Non-goals

- Guaranteed survival against hostile kernel/root
- Full SIEM / enterprise SOAR
- Built-in aggressive internet scanning
- Windows / macOS agents

See also [SECURITY.md](../SECURITY.md), [AGENT_PROTECT.md](AGENT_PROTECT.md), [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [SUPPLY_CHAIN_STORY.md](SUPPLY_CHAIN_STORY.md).
