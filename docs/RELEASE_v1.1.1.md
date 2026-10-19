# SysSpectogram v1.1.1 — Friend protect path

Follow-up to [v1.1.0](RELEASE_v1.1.0.md): protection that survives closing the app, headless day-0 without git, helper from release, safer never-ban.

## Download

From the [v1.1.1 GitHub Release](https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.1.1):

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.1.1_amd64.AppImage` / `.deb` | Desktop Control Center |
| `sysspectogram-1.1.1-*.whl` + musl agent | Stack (Install stack / day-0) |
| `sysspectogram-helper-x86_64-linux` (+ sha256/minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` | Headless one-liners |
| `sysspectogram-helper-packaging.tgz` | Unit + polkit for helper install |

Same-version rule (ADR 0005): GUI, wheel, and agent must match this tag.

## Friend desktop

1. Install AppImage/deb → **Install stack** (sha256; minisign soft if binary missing).
2. Onboarding: language, theme, **role** (seeds FP labels: ssh / nginx / python), mode, **never-ban** (Detect my IP or paste), Telegram.
3. Finish enables **background protect** (`systemd --user`, real mode — not dry-run).
4. Home shows linger hint if needed: `loginctl enable-linger $USER`.
5. Settings: update stack / optional helper from release.

## Headless VPS

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/scripts/friend-day0.sh | bash -s -- v1.1.1
loginctl enable-linger $USER
```

Optional helper:

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/scripts/install-helper-from-release.sh | sudo bash -s -- v1.1.1
```

Then: `python -m sysspectogram menu`. Details: [FRIEND.md](FRIEND.md).

## Notable changes since v1.1.0

- User systemd **protect** unit (no `--dry-run`); Exit leaves it running when active
- Onboarding / Home **Start** → enable that unit
- Never-ban required outside observe; Detect my public IP
- Role step seeds process-label FP pack
- Bootstrap minisign soft-fail; linger documented in Home UI
- CI uploads helper + friend scripts on the release

## Docs

[FRIEND.md](FRIEND.md) · [HOME.md](HOME.md) · [SECURITY.md](../SECURITY.md) · [CONTROL_CENTER.md](CONTROL_CENTER.md)
