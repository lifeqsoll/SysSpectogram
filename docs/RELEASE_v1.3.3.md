# SysSpectogram v1.3.3

Follow-up to [v1.3.2](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.2.md). Fixes the broken desktop Cargo.lock bump, friend install config path, INSTALL docs, and remaining audit holes.

Docs: [INSTALL](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL.md) · [INSTALL (RU)](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL_RU.md) · [INSTALL with AI](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/INSTALL_WITH_AI.md)

---

## Assets (after CI)

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.3.3_amd64.AppImage` / `.deb` | Desktop |
| Fleet Hub AppImage / `.deb` / `.dmg` / `.exe` (+ verify when `.minisig` published) | Fleet |
| `sysspectogram-1.3.3-*.whl` + musl agent (+ sha256 / minisig) | Stack |
| `sysspectogram-helper-x86_64-linux` (+ sha256 / minisig) | Optional polkit helper |
| `friend-day0.sh` / `install-helper-from-release.sh` (+ minisig) | Headless |
| `SHA256SUMS` / `SHA256SUMS.desktop` + `.minisig` | Required (`sha256sum -c` works without `dist/`) |

GUI, wheel, and agent must match this tag.

---

## Highlights

- **Release fix:** Cargo.lock no longer rewrites third-party crates on bump (`proc-macro-crate`); CI requires `cargo metadata --locked`
- **Friend install:** `configure` / `home env` write under `$SYSSPECTOGRAM_HOME`; `friend-day0.sh --no-menu` / non-TTY exits 0 without menu
- **H-01:** minisign trusted comment `sysspectogram <tag> <file>`; install refuses mismatch / downgrade
- **Web:** unauth `/api/unlock` rate-limited (429); CSP header; Chart.js vendored
- **Auth:** non-greedy cert IP parse; `accepted_unparsed` alerts
- **Docs:** admin `--ip` for never_ban, observe→soft, signed friend-day0 (no `curl | bash`), full RU parity

---

## Install

**Desktop:** AppImage/`.deb` for **v1.3.3** → verify minisign → Install stack → onboarding → Start protection.

**VPS:**

```bash
# download friend-day0.sh + .minisig from the release, then:
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
bash friend-day0.sh v1.3.3 --no-menu
export SYSSPECTOGRAM_HOME="${HOME}/.local/share/sysspectogram"
"${SYSSPECTOGRAM_HOME}/.venv/bin/python" -m sysspectogram configure --accept-recommended --role ssh
```

**Existing install:**

```bash
python -m sysspectogram home update --tag v1.3.3
```

Prefer `docs/INSTALL.md`. Always pin a real tag — never floating `main`.

---

## After upgrade

1. Re-run configure if role was stuck on `generic-linux` after a wheel install
2. Helper installs from older tags without a matching trusted comment are refused
3. Never-ban: seed with your admin SSH IP (`--ip`), not the VPS egress IP

---

## Links

- Tag: https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.3.3
- Previous: [v1.3.2](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.2.md) · [v1.3.1](https://github.com/lifeqsoll/SysSpectogram/blob/main/docs/RELEASE_v1.3.1.md)
