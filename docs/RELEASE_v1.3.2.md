# SysSpectogram v1.3.2

Follow-up to [v1.3.1](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.1.md). Closes leftovers from the Grok verify pass and ships install docs for humans and AI agents. **Compatible with 1.3.x** — drop-in over 1.3.0 / 1.3.1.

Docs: [INSTALL](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL.md) · [INSTALL (RU)](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL_RU.md) · [INSTALL with AI](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL_WITH_AI.md) · [FRIEND](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/FRIEND.md)

---

## Assets (after CI)

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.3.2_amd64.AppImage` / `.deb` | Desktop |
| `sysspectogram-1.3.2-*.whl` + musl agent (+ sha256 / minisig) | Stack |
| `sysspectogram-helper-x86_64-linux` (+ sha256 / minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` (+ minisig) | Headless |
| `SHA256SUMS` / `SHA256SUMS.desktop` + `.minisig` | Required |

GUI, wheel, and agent must match this tag.

---

## Highlights

- **Web unlock:** `/api/unlock` no longer mints `ss_session` for unauthenticated loopback — needs Bearer/session or a **correct** unlock code (wrong codes no longer open a session)
- **Control Center:** minisign via absolute `/usr/bin/minisign`; override `SYSSPECTOGRAM_GITHUB_REPO` only with `SYSSPECTOGRAM_DEV=1`
- **Auth:** SSH certificate `Accepted` lines with spaces in principal/ID; polkit helper `service` → `auth_admin`
- **Docs:** three install paths (human EN/RU + AI prompt), README entry points, docs liveness test

---

## Install

**Desktop:** AppImage/`.deb` for **v1.3.2** → Install stack (same tag) → onboarding → Start protection.

**VPS:**

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.2/scripts/friend-day0.sh | bash -s -- v1.3.2
loginctl enable-linger $USER
```

**Existing install:**

```bash
python -m sysspectogram home update --tag v1.3.2
```

**Helper (optional):**

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.3.2/scripts/install-helper-from-release.sh | sudo bash -s -- v1.3.2
```

Prefer `docs/INSTALL.md` (or `INSTALL_WITH_AI.md` if an agent is doing the install). Always pin a real tag — never floating `main`.

---

## After upgrade

1. Web unlock still works with Bearer or the real unlock code; unauthenticated wrong codes stay closed
2. Helper / friend scripts still require minisign verify
3. Existing 1.3.0 / 1.3.1 configs need no migration

---

## Links

- Tag: https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.3.2
- Previous: [v1.3.1](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.1.md) · [v1.3.0](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.0.md)
