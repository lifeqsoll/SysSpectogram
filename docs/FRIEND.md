# Friend path — AppImage or VPS menu

Two supported ways to run SysSpectogram without living in git/cargo.

## Desktop (Linux GUI)

1. Download **AppImage** or **`.deb`** from the [matching GitHub Release](https://github.com/lifeqsoll/SysSpectogram/releases).
2. Open Control Center → **Install stack** (needs `python3` + `venv`; optional `minisign`).
3. Onboarding: language, mode, **never-ban IPs** (required for soft/full/isolate), Telegram.
4. Finish enables **background protect** (`systemd --user`, real mode — not dry-run).
5. On Home: linger warning if needed (`loginctl enable-linger $USER`). Optional: Settings → install privileged helper from release (pkexec, no git).

Update later: Settings → **Update stack from GitHub**, or re-run Install stack.

**Start protection** on Home also enables the same background unit (not a dry-run child).

## Headless VPS (SSH) — day-0 one-liner

```bash
# python3 + python3-venv + curl + minisign  (use the *tag*, never main)
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/friend-day0.sh | bash -s -- v1.2.0

# once per user (otherwise user systemd dies on logout):
loginctl enable-linger $USER
```

Day-0 verifies **SHA-256 and minisign** (embedded pubkey, same as Control Center). Missing `.minisig` on the release → install refuses.

This downloads the release wheel into `~/.local/share/sysspectogram`, creates a venv, installs, then opens `python -m sysspectogram menu`.

Zapret-like numbered menu:

- Status / health  
- Protect service (`systemd --user`)  
- Mode / never-ban / Telegram  
- Unlock code / checklist (includes Kirk / baseline hints)  
- **Under-scan** — host soft-mitigation (lockdown + optional SYN rate-limit; **not** anti-DDoS)  
- Update stack from GitHub tag  

More: [HOST_MITIGATION.md](HOST_MITIGATION.md) · [KIRK.md](KIRK.md) · [FLEET.md](FLEET.md) (many VPS). Set never-ban before soft/full or Under-scan.

Non-interactive:

```bash
export SYSSPECTOGRAM_HOME=~/.local/share/sysspectogram
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram protect enable
python -m sysspectogram home settings --changes '{"response.never_ban_cidrs":"x.x.x.x/32"}'
python -m sysspectogram home update --tag v1.2.0
```

## Privileged helper (optional, no git)

```bash
curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.2.0/scripts/install-helper-from-release.sh | sudo bash -s -- v1.2.0
```

Or from Control Center Settings (pkexec). Downloads `sysspectogram-helper-x86_64-linux` + unit/polkit from the tag.

Geek Day-0 wizard remains: `python -m sysspectogram configure`.

## Same-version rule

GUI version, wheel, and musl agent must match the release tag (ADR 0005). No `git clone` on the VPS for friends.
