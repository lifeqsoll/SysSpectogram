# SysSpectogram v1.3.0 — Security hardening (breaking vs 1.2.x)

Follow-up to [v1.2.2](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.2.2.md). Closes residual auth.log / update / web / pair / kirk gaps after the 1.2.2 security pass. **Not fully compatible with 1.2.x** — hence **1.3.0**.

Docs: [FRIEND](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/FRIEND.md) · [FLEET](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/FLEET.md) · [HOME](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/HOME.md) · [ADR 0005](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/adr/0005-signed-bundle-not-git.md)

---

## Assets (after CI)

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.3.0_amd64.AppImage` / `.deb` | Desktop |
| `sysspectogram-1.3.0-*.whl` + musl agent (+ sha256 / minisig) | Stack |
| `sysspectogram-helper-x86_64-linux` (+ sha256 / minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless |
| `SHA256SUMS` / `SHA256SUMS.desktop` + `.minisig` | Required |

GUI, wheel, and agent must match this tag. Do **not** use **v1.2.0**.

---

## Breaking vs 1.2.x

| Area | Change |
| --- | --- |
| Updates | Both wheel + agent `.minisig` required; embedded pubkey only; refuse downgrade |
| Wheel pubkey | Shipped as `sysspectogram/resources/keys/SysSpectogram.minisign.pub` |
| Web | Host on snapshot/status/stream/unlock/action; JSON + `X-SS-CSRF` on unlock/action |
| Pair | `home pair-remote` needs TTY or `--unlock-code`; fleet `ssh -tt` |
| never_ban | Scrubbed on load; reject `::ffff:…`, `0.0.0.0/8`, loopback nets |
| kirk isolate | Validate all CIDRs **before** any nft drop table |

---

## Highlights

- **Auth:** anchored sshd / `sshd-session` / RFC3339; no username-inject ban; key login (`ssh2: ALG SHA256:…`) works again
- **Updates:** minisign pubkey in the wheel; CC bootstrap refuses downgrade
- **Web:** DNS-rebinding Host fail-closed; unlock needs JSON + CSRF
- **Fleet:** `SshResult.json` reads stdout/stderr separately (pretty JSON + `Connection closed`); outer object wins over nested
- **Kirk / lockdown:** bad CIDRs refuse before nft; `kirk.allow_ssh_cidrs` validated on write / YAML string OK

---

## Install

**Desktop:** AppImage/`.deb` for **v1.3.0** → Install stack (same tag) → onboarding → Start protection.

**VPS:**

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.0/scripts/friend-day0.sh | bash -s -- v1.3.0
loginctl enable-linger $USER
```

**Existing install:**

```bash
python -m sysspectogram home update --tag v1.3.0
```

**Helper (optional):**

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.0/scripts/install-helper-from-release.sh | sudo bash -s -- v1.3.0
```

Unsigned / bad signature / downgrade → refused.

---

## After upgrade

1. Unlock / pair still works (`state/unlock.code`, CSRF on web unlock)
2. Key SSH login still alerts if enabled
3. Set valid `kirk.allow_ssh_cidrs` before kirk auto-isolate
4. Fleet pair: console TTY or `--unlock-code`

---

## Verify assets

```bash
sha256sum -c SHA256SUMS
minisign -Vm sysspectogram-*-py3-none-any.whl -p SysSpectogram.minisign.pub
minisign -Vm sysspectogram-agent-x86_64-linux-musl -p SysSpectogram.minisign.pub
```
