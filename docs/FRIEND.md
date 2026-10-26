# Friend path — AppImage or VPS menu

Two supported ways to run SysSpectogram without living in git/cargo.

## Desktop (Linux GUI)

1. Download **AppImage** or **`.deb`** from the [matching GitHub Release](https://github.com/lifeqsoll/SysSpectogram/releases/latest) (`<LATEST_TAG>`).
2. Verify with `.minisig` when published; if desktop assets are missing on that release, **stop** — see [INSTALL.md](INSTALL.md) §B.
3. Open Control Center → **Install stack** (needs `python3` + `venv`; **minisign** when `.minisig` exists).
4. Onboarding: language, mode, **never-ban IPs** (required for soft/full/isolate), Telegram.
5. Finish enables **background protect** (`systemd --user`, real mode — not dry-run).
6. On Home: linger warning if needed (`loginctl enable-linger $USER`). Optional: Settings → install privileged helper from release (pkexec, no git).

Update later: Settings → **Update stack from GitHub**, or re-run Install stack.

**Start protection** on Home also enables the same background unit (not a dry-run child).

## Headless VPS (SSH) — signed day-0

```bash
# python3 + python3-venv + curl + minisign; tag from releases/latest — never main
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/friend-day0.sh.minisig"
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh "$TAG"
loginctl enable-linger "$USER"
```

Day-0 verifies **SHA-256 and minisign** (embedded pubkey, same as Control Center). Missing `.minisig` on the release → install refuses.

This downloads the release wheel into `~/.local/share/sysspectogram`, creates a venv, installs, then opens `python -m sysspectogram menu`. Press **0** to quit the menu and continue [INSTALL.md](INSTALL.md) §1.3, or use `bash friend-day0.sh "$TAG" --no-menu` when your release script supports it.

Zapret-like numbered menu:

- Status / health  
- Protect service (`systemd --user`)  
- Mode / never-ban / Telegram  
- Unlock code / checklist (includes Kirk / baseline hints)  
- **Under-scan** — host soft-mitigation (lockdown + optional SYN rate-limit; **not** anti-DDoS)  
- Update stack from GitHub tag  

More: [HOST_MITIGATION.md](HOST_MITIGATION.md) · [KIRK.md](KIRK.md) · [FLEET.md](FLEET.md) (many VPS). Seed never-ban with `--ip` (admin SSH source) before soft/full or Under-scan.

Non-interactive:

```bash
export SYSSPECTOGRAM_HOME=~/.local/share/sysspectogram
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
python -m sysspectogram protect enable
python -m sysspectogram home update --tag <LATEST_TAG>
```

## Privileged helper (optional, no git)

```bash
TAG=<LATEST_TAG>
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh"
curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh.minisig"
minisign -Vm install-helper-from-release.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
sudo bash install-helper-from-release.sh "$TAG"
```

Or from Control Center Settings (pkexec). Downloads `sysspectogram-helper-x86_64-linux` + unit/polkit from the tag.

Geek Day-0 wizard remains: `python -m sysspectogram configure`.

## Same-version rule

GUI version, wheel, and musl agent must match the release tag (ADR 0005). No `git clone` on the VPS for friends.
