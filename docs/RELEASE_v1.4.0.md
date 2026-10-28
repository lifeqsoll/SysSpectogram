# SysSpectogram v1.4.0

Minor release after [v1.3.3](RELEASE_v1.3.3.md). Friend-path auto-ban works end-to-end: **nft named sets**, bans through **sysspectogram-helper** (Unix group, no polkit prompt), honest health, admin protect + soft-mode rollback. Desktop/fleet release signing and install URLs fixed.

Docs: [INSTALL](INSTALL.md) · [INSTALL (RU)](INSTALL_RU.md) · [INSTALL with AI](INSTALL_WITH_AI.md) · [FAQ](FAQ.md) · [Comparison](COMPARISON.md) · [CHANGELOG](../CHANGELOG.md)

---

## Assets (after CI)

| Asset | Use |
| --- | --- |
| `SysSpectogram_Control_Center_1.4.0_amd64.AppImage` / `.deb` (+ `.minisig`) | Desktop — note **no** `v` in the filename (`VER="${TAG#v}"`) |
| Fleet Hub AppImage / `.deb` / `.dmg` / `.exe` (+ `.minisig`, one `SHA256SUMS.fleet-center`) | Fleet (signed in final `fleet-sign` job) |
| `sysspectogram-1.4.0-*.whl` + musl agent (+ sha256 / minisig) | Stack |
| `sysspectogram-helper-x86_64-linux` (+ sha256 / minisig) | **Required** for soft/full on friend (non-root) path |
| `friend-day0.sh` / `install-helper-from-release.sh` (+ minisig) | Headless |
| `SHA256SUMS` / `SHA256SUMS.desktop` / `SHA256SUMS.fleet-center` + `.minisig` | Verify (`sha256sum -c` + minisign trusted comment) |

GUI, wheel, agent, and helper must match **this tag**. Trusted comment shape: `sysspectogram v1.4.0 <file>`.

---

## Highlights

### Critical — bans that work (Phase 0)

- **F-01** — nftables **named sets** `ban4` / `ban6` with kernel timeouts (no comment-rule / handle parsing).
- **F-02** — Non-root guard bans via helper ops `ban.add` / `ban.del` / `ban.list` / `ban.selftest`, authorized by group **`sysspectogram`** (not polkit).
- **F-05** — Failures never look like success: Telegram/CLI use `BAN FAILED` / `BAN SKIPPED`, not `AUTO-BAN nft failed…`.
- **F-04** — `home health` checks **`ban_backend`** (and **`ssh_source`**); soft/full/isolate → `ok=false` if bans or SSH feed cannot work.
- CI job **`nft-real`**: real nft under `unshare -n`.

### Detection & admin safety (Phase 1)

- **F-03** — SSH auth from journal (`ssh` / `sshd` / `sshd-session`) + helper **`auth.tail`** when the user is not in `systemd-journal`.
- **F-07** — `is_protected` (never_ban, host/self addresses, active SSH sessions); soft/full/isolate writes `mode_pending.json` and auto-rolls back to observe unless `home confirm-mode` (or `--no-rollback`).
- `home settings` refuses soft/full/isolate without helper when not root.

### Packaging & release (Phases 2–3)

- **F-06** — `web/static/*` in the wheel (`GET /` no longer 404 after pip install).
- **R-10** — Fleet matrix only uploads artifacts; **`fleet-sign`** builds one `SHA256SUMS.fleet-center` and minisigns; **`verify-release`** checks every asset.
- **R-15** — Install docs use `VER="${TAG#v}"` for Control Center filenames (fixes 404 from `_v1.x.x_`).

### Operator CLI & leftovers (Phases 4–6)

- **`bans list|unban|test-ban`**, **`doctor`**, **`perimeter replay --file`**, **`home uninstall`**, **`home confirm-mode`**.
- Unlock: correct code always accepted; rate-limit only on failures (no in-handler sleep).
- CSP allows Telegram Web `frame-ancestors` where Mini App needs it.
- friend-day0: trusted-comment check, `${USER:-$(id -un)}`, no `curl|bash` in the header.
- **`response.ban_increment`** — repeated-offender TTL ×2ⁿ capped by `max_ban_ttl_sec`.
- R-09 / R-11 / R-12 / R-13 / R-14 / R-17 and related INSTALL/SECURITY fixes — see [CHANGELOG](../CHANGELOG.md).

### ML (Phase 7) — experimental

- Light **`sysspectogram.ml.host_baseline`** (per-host MAD robust-z; no alerts during baseline).
- Full CNN/split/eval rewrite **not** claimed for 1.4.0 — status stays experimental; gates in [EVAL.md](EVAL.md).

### Docs / community (Phase 8)

- [CHANGELOG.md](../CHANGELOG.md), CONTRIBUTING, Code of Conduct, issue/PR templates, Dependabot.
- [COMPARISON.md](COMPARISON.md), [FAQ](FAQ.md) / [FAQ_RU](FAQ_RU.md); README lead clarifies Beta + friend path.
- [SECURITY.md](../SECURITY.md) + [THREAT_MODEL.md](THREAT_MODEL.md): supported 1.4.x / 1.3.x; helper ban-group threat note.

### Intentionally deferred / incomplete

- Full container+SSH e2e (workflow `e2e-install.yml` is a **smoke** skeleton, not the full INSTALL §1 lab from the audit).
- Full ML pipeline leak fixes / beating offline baselines (experimental only).
- README not fully trimmed to ~300 lines (lead + quick start rewritten).

---

## Breaking / behaviour changes vs 1.3.3

Compatible CLI names and JSON fields; behaviour shifts operators must know:

1. **Soft/full/isolate on friend path requires helper** (user in group `sysspectogram`) or root. Without it, settings/health fail closed.
2. Auto-ban goes through **nft sets** / helper — not per-rule comments.
3. Mode switch schedules **auto-rollback** unless confirmed (`home confirm-mode` / `--no-rollback`).
4. Desktop asset names: `…_1.4.0_…`, not `…_v1.4.0_…`.

Threat model for group membership: [SECURITY.md](../SECURITY.md) § Ban operations · [THREAT_MODEL.md](THREAT_MODEL.md) § Helper ban path.

---

## Install

**Desktop:** AppImage/`.deb` for **v1.4.0** → verify minisign → Install stack → onboarding → Start protection. Filenames use `1.4.0` without a leading `v`.

**VPS (friend):**

```bash
# download friend-day0.sh + .minisig from the release, then:
minisign -Vm friend-day0.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
# confirm Trusted comment: sysspectogram v1.4.0 friend-day0.sh
bash friend-day0.sh v1.4.0 --no-menu
export SYSSPECTOGRAM_HOME="${HOME}/.local/share/sysspectogram"
source "${SYSSPECTOGRAM_HOME}/.venv/bin/activate"
python -m sysspectogram configure --accept-recommended --role ssh
python -m sysspectogram home seed-never-ban --ip "${SSH_CONNECTION%% *}"
# helper required before soft:
sudo bash install-helper-from-release.sh v1.4.0
sudo usermod -aG sysspectogram "$USER"   # then re-login
loginctl enable-linger "$USER"           # or: sudo loginctl enable-linger "$USER"
python -m sysspectogram protect enable
python -m sysspectogram home settings --changes '{"response.mode":"soft"}'
python -m sysspectogram home confirm-mode   # within ~10 minutes
python -m sysspectogram home health
```

Prefer full steps in [INSTALL.md §1](INSTALL.md#1-quick-start-one-ubuntudebian-vps).

**Existing install:**

```bash
python -m sysspectogram home update --tag v1.4.0
# reinstall helper for ban.* / auth.tail if you use soft mode
sudo bash install-helper-from-release.sh v1.4.0
```

Always pin a real tag — never floating `main`.

---

## After upgrade

1. Install/update **helper** and ensure your user (or the protect unit user) is in group **`sysspectogram`**; re-login so the group applies.
2. Re-seed **never_ban** with the admin SSH client IP (`--ip`), not only VPS egress.
3. After switching to soft/full, run **`home confirm-mode`** or the mode rolls back to observe.
4. `home health`: expect `ban_backend` and `ssh_source` ok before trusting auto-ban.
5. Desktop downloads: use `VER=1.4.0` names from the asset list, not `v1.4.0` inside the filename.

---

## Verify release (operators)

```bash
# after downloading assets for tag v1.4.0:
sha256sum -c SHA256SUMS
sha256sum -c SHA256SUMS.desktop   # if present
minisign -Vm sysspectogram-1.4.0-py3-none-any.whl \
  -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
# Trusted comment must be: sysspectogram v1.4.0 <filename>
```

---

## GitHub release body (paste into `gh release edit`)

```markdown
## SysSpectogram 1.4.0

Friend-path bans that work: nft **named sets**, helper bans (group `sysspectogram`), honest `home health`, admin protect + mode rollback. Fleet/desktop signing fixed; web UI ships in the wheel.

### Must know
- Soft/full needs **helper** + group membership (or root).
- Confirm soft with `home confirm-mode` or it rolls back.
- Desktop files: `SysSpectogram_Control_Center_1.4.0_…` (no `v` in the name).

### Docs
- Notes: https://github.com/lifeqsoll/SysSpectogram/blob/v1.4.0/docs/RELEASE_v1.4.0.md
- Install: https://github.com/lifeqsoll/SysSpectogram/blob/v1.4.0/docs/INSTALL.md
- Changelog: https://github.com/lifeqsoll/SysSpectogram/blob/v1.4.0/CHANGELOG.md

ML host baseline is **experimental** — see docs/EVAL.md.
```

---

## Links

- Tag: https://github.com/lifeqsoll/SysSpectogram/releases/tag/v1.4.0
- Previous: [v1.3.3](RELEASE_v1.3.3.md) · [v1.3.2](RELEASE_v1.3.2.md) · [v1.3.1](RELEASE_v1.3.1.md)
