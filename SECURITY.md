# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.9.x | yes |
| 0.8.x | security fixes |
| 0.7.x | security fixes only |
| 0.6.x | security fixes only |
| 0.5.x | best-effort |
| < 0.5 | best-effort |

## Report a vulnerability

Email or open a **private** GitHub security advisory. Do not file public issues for
exploits against live hosts.

Target response: triage within 72 hours.

## Trust boundaries (honest)

- Default `response.mode: observe` does not auto-ban.
- `kirk.auto_isolate` is off by default and requires `allow_ssh_cidrs` **and** a
  valid agent HMAC on critical rules.
- Agent UDS: mode 0600 + same-UID PEERCRED + PID allowlist + HMAC-SHA256
  for critical rules including kirk and `agent_unexpected_root`
  (`state/agent_hmac.secret` / `SYSSPECTOGRAM_AGENT_HMAC`).
- Binary exe seal rejects swapped agent processes.
- Telegram control plane requires console unlock code.
- Profile packs: verify SHA-256 and minisign in production; HMAC `.sig` remains
  compatible for local packs.
- Model manifests can be enforced before any Torch/ONNX/safe-artifact deserialization;
  `cnn.pt` uses `weights_only=True` only. Legacy joblib requires
  `SYSSPECTOGRAM_ALLOW_JOBLIB=1` and is refused under enforce. See
  [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) and [RELEASE_v0.9.0.md](docs/RELEASE_v0.9.0.md).
- Alert sinks can mirror events off-box (`alerts.sinks`); local jsonl alone is not
  forensic storage.
- Hybrid watchdog: Phoenix userspace + optional DKMS module (default off).
  See [AGENT_PROTECT.md](docs/AGENT_PROTECT.md) and
  [packaging/kmod/sysspectogram_wd/README.md](packaging/kmod/sysspectogram_wd/README.md).
- Distro guard and monitor units run as the dedicated `sysspectogram` account;
  the packaged agent defaults to userspace and does not receive eBPF
  capabilities unless an operator installs a reviewed drop-in.

## Same-host ceiling

If an attacker already has root on the monitored VPS, they can stop systemd
units and delete local files. SysSpectogram aims to make that **noisy** (remote
sinks, Dead-man, phoenix respawn) — not impossible. Do not market it as
unkillable EDR.

Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What we will not ship

- Rootkit/malware samples for "tests"
- Claims of being rootkit-proof
- Mandatory phone-home telemetry

See [TRUST.md](docs/TRUST.md), [AGENT_PROTECT.md](docs/AGENT_PROTECT.md), [ROOT_WATCH.md](docs/ROOT_WATCH.md), [KIRK.md](docs/KIRK.md).
