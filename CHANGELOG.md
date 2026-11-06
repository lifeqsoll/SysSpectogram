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
