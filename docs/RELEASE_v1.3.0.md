# SysSpectogram v1.3.0 — Security hardening (breaking vs 1.2.x)

Follow-up to [v1.2.2](RELEASE_v1.2.2.md). This release closes the residual auth.log / update / web / pair / kirk gaps found after the 1.2.2 security pass. Behavior is **not** fully compatible with 1.2.x — bump the major minor to **1.3.0** on purpose.

Companion docs: [FRIEND.md](FRIEND.md) · [FLEET.md](FLEET.md) · [HOME.md](HOME.md) · [ADR 0005](adr/0005-signed-bundle-not-git.md).

---

## Download

Assets appear on the [v1.3.0 release](https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.3.0) after CI finishes.

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.3.0_amd64.AppImage` / `.deb` | Desktop app |
| `sysspectogram-1.3.0-*.whl` + musl agent (+ sha256/minisig) | Stack (Install stack / day-0 / `home update`) |
| `sysspectogram-helper-x86_64-linux` (+ sha256/minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless one-liners |
| `SHA256SUMS` / `SHA256SUMS.desktop` + `.minisig` | Required for install/update |

Same-version rule ([ADR 0005](adr/0005-signed-bundle-not-git.md)): GUI, wheel, and agent must match this tag.

Do **not** use tag **v1.2.0** (broken install). Prefer **v1.3.0**.

---

## Breaking changes vs 1.2.x

| Area | 1.2.x | 1.3.0 |
| --- | --- | --- |
| Updates | Soft / incomplete signature path | **Both** wheel + agent `.minisig` required; embedded pubkey only; refuse downgrade |
| Wheel pubkey | Looked under `control-center/.../keys/` | Shipped as package data `sysspectogram/resources/keys/SysSpectogram.minisign.pub` |
| Web API | Host/CSRF mainly on `/api/action` | Host on snapshot/status/stream/unlock/action; JSON + CSRF on unlock/action; `[::1]:port` OK |
| Pairing | CLI always; pair_* on socket earlier removed | `home pair-remote` needs **TTY** or `--unlock-code`; fleet uses `ssh -tt` |
| never_ban | Wide CIDR could load from stale overlay/YAML | Scrubbed on load (warn); Rust/Python reject `::ffff:…` / `0.0.0.0/8` / loopback nets |
| kirk isolate | Bad CIDR could leave policy-drop table | All CIDRs validated **before** any nft mutation; `kirk.allow_ssh_cidrs` validated on write |

---

## Highlights

### Auth.log / autoban

- Anchored sshd / `sshd-session` / RFC3339 lines; end-anchored `from IP port N`.
- Username inject via `Disconnected` / `Connection closed` no longer yields a ban IP.
- **Accepted publickey** lines with `ssh2: ALG SHA256:…` tails parse again (key login alerts).

### Signed home update / bootstrap

- Minisign pubkey in the wheel; day-0 / pip installs no longer fail with “embedded pubkey missing”.
- Control Center `bootstrap.rs` refuses version downgrade (matches Python).

### Web

- DNS-rebinding Host allowlist on data APIs; empty Host fails closed.
- Unlock requires `Content-Type: application/json` + `X-SS-CSRF: 1` (local UI updated).

### Fleet / SSH JSON

- `SshResult.json()` loads stdout then stderr separately (pretty `indent=2` + `Connection to … closed.` on stderr).
- Top→bottom `raw_decode` so nested objects inside a list do not win over the outer object.

### Kirk / lockdown

- Invalid allow CIDRs refuse **before** `nft add table` / drop policy.
- `kirk.allow_ssh_cidrs` in settings schema + helper allowlist; YAML string form parsed as CIDRs (not characters).

---

## Install / upgrade

### Friend desktop

1. Download AppImage/`.deb` for **v1.3.0**.
2. **Install stack** for the **same** tag (needs `minisign` for verify).
3. Onboarding → never-ban → Start protection.

### Headless VPS

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.0/scripts/friend-day0.sh | bash -s -- v1.3.0
loginctl enable-linger $USER
```

From an existing install:

```bash
python -m sysspectogram home update --tag v1.3.0
```

Unsigned or wrongly signed releases are refused. Downgrade to an older tag is refused.

Optional helper:

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.0/scripts/install-helper-from-release.sh | sudo bash -s -- v1.3.0
```

---

## Operator checklist after upgrade

1. Confirm `state/unlock.code` still rotates (pair / Telegram unlock).
2. Web Mini App / local UI: unlock still works (CSRF header).
3. Key-based SSH login should still fire `new_login_source` if enabled.
4. If you use kirk isolate: set valid `kirk.allow_ssh_cidrs` before enabling auto-isolate.
5. Fleet pair: console TTY or `--unlock-code`; hub `fleet pair-start` uses `-tt`.

---

## Verify release assets

```bash
# after CI attaches assets
sha256sum -c SHA256SUMS
minisign -Vm sysspectogram-*-py3-none-any.whl -p path/to/SysSpectogram.minisign.pub
minisign -Vm sysspectogram-agent-x86_64-linux-musl -p path/to/SysSpectogram.minisign.pub
```

---

## Thanks

Security review rounds after e2d3b81 / 0148e25 / 14febd0 / 4ae1cdc — auth inject, signed updates, Host/CSRF, kirk lockout, fleet JSON.
