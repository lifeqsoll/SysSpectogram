# Security Policy

SysSpectogram is a **self-hosted** Linux host guard. This document is the operator-facing security policy: what we support, how to report issues, what we actually trust, and what we will never claim.

For the deeper model (assets, adversaries, residual risk) see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). For signing and manifests see [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

## Supported versions

| Version | Supported |
| --- | --- |
| **1.4.x** | Full support (fixes + hardening) |
| **1.3.x** | Security fixes |
| **1.2.x** | Security fixes |
| 1.1.x | Security fixes only |
| 1.0.x | Best-effort; please upgrade |
| &lt; 1.0 | Unsupported |

Prefer the latest tagged release from [GitHub Releases](https://github.com/lifeqsoll/SysSpectogram/releases). Friend installs should use the matching **AppImage** / **`.deb`** plus the signed wheel/agent for that same tag — not a random `main` checkout on a production VPS.

## Report a vulnerability

**Do not** open a public issue for an exploit that can harm live hosts (RCE, privilege escalation, unlock bypass, forged agent alerts, supply-chain forge, etc.).

Preferred channels:

1. **[Private vulnerability reporting](https://github.com/lifeqsoll/SysSpectogram/security/advisories/new)** (GitHub Security Advisories — preferred).
2. Or email the maintainer address listed on the GitHub profile / release notes.

Please include:

- Affected version / commit / package (AppImage, wheel, agent binary).
- Host OS and how you run the stack (systemd, Control Center child, dry-run, …).
- Clear reproduction steps or a minimal PoC.
- Impact (who can trigger it, what they gain).
- Whether you plan a public write-up and your preferred timeline.

**Target response:** triage acknowledgement within **72 hours**. Fix timing depends on severity and whether a coordinated disclosure date is agreed.

We welcome responsible disclosure. We do **not** run a paid bug bounty.

## Scope (in / out)

**In scope**

- Guard / agent / helper / Control Center behavior on a machine the reporter controls (or has explicit permission to test).
- Bypass of Telegram / web / control-socket unlock.
- Forging critical agent alerts without a valid HMAC / PEERCRED path.
- Tampering with release artifacts that still verify under our documented checks.
- Logic bugs that auto-ban the operator despite a correct `never_ban` allowlist.
- SSRF / private-IP reachability via configured alert sinks when defaults should block it.

**Out of scope**

- Attacks that already assume **root on the same host** and then stop units / delete state (see *Same-host ceiling*).
- Social engineering of BotFather tokens or leaked `.env` files.
- DoS by flooding a deliberately enabled public web UI without network controls.
- Issues only present in unreleased `main` unless they also affect a tagged release.
- Third-party profile packs or models you installed without verifying signatures.

## Trust boundaries (honest)

Defaults are intentionally cautious.

### Response and lockout

- Default `response.mode: observe` — notify only, no auto-ban.
- Soft / aggressive / isolate modes still honour `response.never_ban_cidrs` (one or many IPs/CIDRs; bare IP normalises to `/32` or `/128`). Set your admin path **before** enabling auto-ban.
- `kirk.auto_isolate` is **off** by default and needs both `kirk.allow_ssh_cidrs` **and** a valid agent HMAC on allowlisted critical rules.

### Agent authenticity

- Agent Unix datagram socket: mode `0600`, same-UID `PEERCRED`, optional PID allowlist, HMAC-SHA256 on critical rules (kirk hide/drift/IMA, `agent_unexpected_root`, clean shutdown, agent/guard down, …).
- Secret: `state/agent_hmac.secret` or `SYSSPECTOGRAM_AGENT_HMAC`.
- Binary exe seal rejects a swapped agent process that still holds the PID.

### Control plane (Telegram / web / local socket)

- Destructive actions require a **console unlock** code shown in Control Center / `state/unlock.code` (never sent in the unlock Telegram notice itself).
- Unlock language follows `ui.lang` once per guard start (no dual EN+RU spam from one process).
- Local SOAR uses `state/control.sock` with the **same** unlock gate as Telegram.
- Multi-VPS fleet control uses **SSH + device tokens** (host pair code); see [docs/FLEET.md](docs/FLEET.md). No public HTTPS control plane.

**Same-UID ceiling for unlock (I-03):** the unlock gate protects a stolen Telegram bot token / Mini App session — **not** malware running as the same Unix user as the guard. That process can already read `state/unlock.code` (mode 0600, owner-only) or the `.env` bot token. Persisted `state/control.unlocked` (only when unlock TTL is 0) accepts the exact marker `1` and refuses symlinks / arbitrary content; it is still same-UID writable by design. Treat same-UID compromise as full control of the guard process.

### Single guard

- Only one guard may hold `state/guard.lock`. A second instance would unlink/rebind the agent socket, miss heartbeats, and flood false `agent_kirk_agent_down` alerts. Control Center refuses to start a second guard when the pidfile is alive.

### Packaged install (AppImage / deb)

- First-run **Install stack** downloads the **same-version** GitHub Release assets (wheel + musl agent). **SHA-256 is required** (`SHA256SUMS` for wheel/agent stack only + agent `.sha256`). Desktop bundles use a separate `SHA256SUMS.desktop` so they cannot overwrite the stack sums file. If a `.minisig` is published for an asset, **minisign must succeed** (install `minisign`; soft-fail is not accepted).
- No runtime `git clone` / `git pull` as the friend install path ([ADR 0005](docs/adr/0005-signed-bundle-not-git.md)).
- Runtime data lives under `~/.local/share/sysspectogram` unless `SYSSPECTOGRAM_HOME` is set.
- Details: [RELEASE_v1.1.1.md](docs/RELEASE_v1.1.1.md), [FRIEND.md](docs/FRIEND.md), [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md).

### Models and packs

- Prefer ONNX / pickle-free artifacts. `cnn.pt` loads with `weights_only=True` only.
- Legacy joblib needs `SYSSPECTOGRAM_ALLOW_JOBLIB=1` and is refused when supply-chain enforce is on.
- Profile packs: verify SHA-256 + minisign in production; local HMAC `.sig` is compatibility only.

### Privilege split

- Control Center never runs as root. System overlays / service control go through `sysspectogram-helper` + **polkit** when the helper is installed.
- Home / Day-0 overlays can live in user-owned `state/user-settings.json` without the helper.
- Distro units for guard/monitor run as the dedicated `sysspectogram` account; the packaged agent defaults to userspace and does not get eBPF capabilities unless an operator adds a reviewed drop-in.

### Ban operations (`sysspectogram` group)

On friend / headless installs the guard often runs **without root**. Auto-ban then uses the helper’s **nft set** path, authorized by Unix group membership (`sysspectogram`), not polkit — so a headless unit never blocks on a desktop pkcheck dialog.

**Threat note:** any local user in group `sysspectogram` (or any process running as that user) can ask the helper to add/remove ban-set members within the helper’s allowlist. Treat group membership like **partial network admin**: do not add untrusted accounts to `sysspectogram`; keep the helper binary and unit files root-owned; prefer a dedicated service user over sharing the group with human login accounts. Compromise of a group member can disrupt SSH reachability to your VPS (DoS), not remote code execution in the helper itself.

### Evidence and sinks

- Local JSONL is convenient, not WORM storage. Remote `alerts.sinks` (HTTPS / syslog) can mirror events off-box; private/link-local sink hosts are blocked unless explicitly allowed.
- Hybrid watchdog (Phoenix userspace; optional DKMS module, default off) aims to make agent death **noisy**, not immortal. See [AGENT_PROTECT.md](docs/AGENT_PROTECT.md).

## Hardening checklist (operators)

1. Install from a **tagged** release; verify minisign / `SHA256SUMS` when you download by hand.
2. Put your SSH / admin IP(s) in **never-ban** before enabling soft/full auto-ban.
3. Keep Telegram unlock required (`telegram.require_console_unlock: true`).
4. Keep the agent HMAC secret mode `0600` and off shared disks.
5. Prefer `response.mode: observe` until charts and alerts look sane.
6. Turn on remote alert sinks if you need evidence after a local wipe.
7. Do not run multiple guards; use one Control Center **Start protection**.
8. Treat imported ML weights as untrusted until you trained them yourself or verified the publisher.

## Same-host ceiling

If an attacker already has **root on the monitored VPS**, they can stop systemd units, kill processes, replace binaries under paths they own, and delete local logs. SysSpectogram tries to make that **noisy** (remote sinks, Dead-man, phoenix respawn, dual-process friction) — **not** impossible.

Do not market or assume “unkillable EDR”, “rootkit-proof”, or “survives hostile kernel”. Out-of-guest visibility (VMI) remains lab / opt-in and is not a production guarantee.

Full write-up: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## What we will not ship

- Rootkit / malware samples “for tests”
- Claims of being rootkit-proof or unkillable
- Mandatory phone-home telemetry (see [TRUST.md](docs/TRUST.md))
- Runtime `git pull` / clone as the supported friend install path
- Process kill / isolate from Telegram without the unlock gate (helper `ban.*` is group-gated for headless auto-ban; interactive SOAR stays unlock-gated in the guard)

## Related docs

| Doc | Topic |
| --- | --- |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, adversaries, residual risk |
| [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) | Manifests, minisign, CI secrets |
| [TRUST.md](docs/TRUST.md) | Privacy / no phone-home |
| [AGENT_PROTECT.md](docs/AGENT_PROTECT.md) | HMAC, seal, phoenix |
| [ROOT_WATCH.md](docs/ROOT_WATCH.md) | Unexpected root |
| [KIRK.md](docs/KIRK.md) | Integrity / isolate |
| [CONTROL_CENTER.md](docs/CONTROL_CENTER.md) | Helper + polkit surface |
| [RELEASE_v1.4.0.md](docs/RELEASE_v1.4.0.md) | Latest release notes |
| [FRIEND.md](docs/FRIEND.md) | Friend install path |
