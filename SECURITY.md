# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.8.x | yes |
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
- Model manifests can be enforced before any Torch/joblib/ONNX deserialization;
  `cnn.pt` uses `weights_only=True` only. See [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).
- Distro guard and monitor units run as the dedicated `sysspectogram` account;
  the packaged agent defaults to userspace and does not receive eBPF
  capabilities unless an operator installs a reviewed drop-in.

## What we will not ship

- Rootkit/malware samples for "tests"
- Claims of being rootkit-proof
- Mandatory phone-home telemetry

See [TRUST.md](docs/TRUST.md), [AGENT_PROTECT.md](docs/AGENT_PROTECT.md), [ROOT_WATCH.md](docs/ROOT_WATCH.md), [KIRK.md](docs/KIRK.md).
