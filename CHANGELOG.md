# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older release write-ups: [docs/RELEASE_v1.4.0.md](docs/RELEASE_v1.4.0.md),
[docs/RELEASE_v1.3.3.md](docs/RELEASE_v1.3.3.md),
[docs/RELEASE_v1.3.2.md](docs/RELEASE_v1.3.2.md),
[docs/RELEASE_v1.3.1.md](docs/RELEASE_v1.3.1.md),
[docs/RELEASE_v1.3.0.md](docs/RELEASE_v1.3.0.md) (and earlier `docs/RELEASE_*.md`).

## [Unreleased]

### Added

- Phase 7 ML honesty: leak-free train/val/test (+ gap), lab filters/balance opt-in, `ml.baselines`, gate vs best baseline, `docs/DATASET.md`, `collect_labeled` scaffold.
- Phase 7.5–7.9: `user_metrics` (FP/day, TTD), plain ML explain, FP suppress after «normal», drift refit controller, ONNX↔torch parity test.

### Changed

- `build-dataset` defaults: no lab filters, no balance; `eval_offline` hard-errors on `windows_format=scaled`; `check_ml_ready` requires fuse > best baseline (PR-AUC + recall@FPR1%).

### Fixed

- `time_to_detect` keeps every anomaly episode (no label overwrite); multi-episode JSON documented in EVAL.
- Drift refit uses the shared `HostBaseline`, bounded memory, wired into guard host path (log only, not HOST ALERT).
- FP-suppress prototypes TTL 7d; drop unused `refit_pending` (IF refit stays on Telegram debounce).
- Plain ML explain reports observations only (no miner/attack diagnosis).
- Ready `HostBaseline.score()` feeds promote-only into `decide_risk` (never suppress fuse; no sample poison on learning ticks).
- Unlock form maxlength matches code length; `home settings` rejects junk `response.mode`; `bans list` fails honestly without privileges; well-known anycast never-ban needs `--force`; LOCKED redacts `/api/status` like snapshot.
- Web `/api/status|snapshot|stream` require session/Bearer (not loopback-unauth); `/api/health` stays public metadata-only.
- `seed-never-ban` expands well-known DNS/anycast (v4/v6) and refuses private/loopback/multicast/… without `--force` (clear reasons).
- Root `bans list` returns `ok:false` when `nft` is missing or both set lists fail (no empty memory success).
- Accept LAN/ULA never_ban with warning; CGNAT warns; anycast check covers CIDRs; prefer `SSH_CONNECTION` when seeding without `--ip`.
- Quote nft rule comments so lockdown/quarantine/shield actually apply; check established rule rc.
- Lockdown/syn-rate-limit use `tcp flags syn / fin,syn,rst,ack` (nft 1.1.x). A failed apply rolls back only the rules that call added.
- `home health` does not treat a host with no journal files as an ssh source, including root (`journalctl` without `-q`).
- `sysspectogram web login` prints the WEB LOGIN CODE only while web is running (pid in `state/web.login`); stopping web deletes the file.
- Kirk isolate DNS is resolver-only; TCP/443 only to `kirk.egress_allow_cidrs` (Telegram ranges by default).
- Set perimeter lockdown flag only after nft succeeds; web returns error on refuse.
- WEB LOGIN CODE (`/api/login`, `state/web.login`) mints read session without control unlock.
- Runtime paths (`state/`/`reports/`/`artifacts/`) resolve under `SYSSPECTOGRAM_HOME`.
- Ban TTL ≤0 / NaN / inf rejected; `test-ban` capped at 1h; POST body Host-before-read + 64KiB limit.
- `home settings` validates types/ranges (schema); corrupt overlay refuses without `--force`; writes use `flock`.
- `kirk_isolate` persists TTL to `state/kirk_isolate.json`, rolls back on allow failure, keeps DNS/443 egress; shield port sweeper honors comment deadlines.
- Web `allow`/`mute`/`quiet` validate IP/TTL/bool; helper rejects IPv4-mapped/broadcast/`240/4` and float TTL; concurrent accept + pkcheck timeout.
- `home health` distinguishes empty ssh source vs no access; non-zero exit when `ok:false`; state dir 0700 / secrets 0600; configure EOF → `--non-interactive`.

## [1.4.0] - 2026-10-28

Full notes: [docs/RELEASE_v1.4.0.md](docs/RELEASE_v1.4.0.md).

### Added

- **F-01** — nftables **named set** bans with kernel timeout (no comment-rule handles).
- **F-02** — Ban path via **sysspectogram-helper** for non-root guard (`sysspectogram` group auth; no polkit prompt on headless VPS).
- **F-03** — SSH auth log sources: classic files + journal (`ssh` / `sshd` units) with helper fallback when needed.
- **F-04** — `home health` / doctor **`ban_backend`** check; soft/full/isolate warn when bans cannot apply.
- **F-05** — Structured ban outcomes so failures never read like success in CLI/Telegram.
- **F-06** — `bans list|unban|test-ban` and **`doctor`** redacted health dump for support.
- **F-07** — `is_protected` (never-ban, active SSH session) and soft-mode **pending rollback** if not confirmed.
- **R-09** — Contributor docs, issue/PR templates, Dependabot, FAQ/COMPARISON, Keep-a-Changelog.
- **`perimeter replay --file`** — offline auth.log parse via `parse_auth_lines` (events only, no ban).
- **`response.ban_increment`** — repeated-offender TTL multiplier (2ⁿ) capped by `max_ban_ttl_sec`.
- **Experimental** `sysspectogram.ml.host_baseline` — per-host MAD robust-z (no alerts during baseline); full ML rewrite still deferred ([docs/EVAL.md](docs/EVAL.md)).

### Changed

- Soft/full auto-ban on friend installs expects **helper installed** (or root) so nft sets can be applied.
- README lead: perimeter + alerts first; host ML marked **experimental** ([docs/EVAL.md](docs/EVAL.md)).
- `home settings` refuses soft/full/isolate without helper (non-root); schedules mode auto-rollback unless `--no-rollback`.

### Security

- [SECURITY.md](SECURITY.md): supported **1.4.x / 1.3.x**, ban-op threat note for `sysspectogram` group.

## [1.3.3] - 2025-03-01

See [docs/RELEASE_v1.3.3.md](docs/RELEASE_v1.3.3.md).
