# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older release write-ups: [docs/RELEASE_v1.5.0.md](docs/RELEASE_v1.5.0.md) (draft),
[docs/RELEASE_v1.4.0.md](docs/RELEASE_v1.4.0.md),
[docs/RELEASE_v1.3.3.md](docs/RELEASE_v1.3.3.md) (and earlier `docs/RELEASE_*.md`).

## [Unreleased]

## [1.5.0] - 2026-11-21 (prep — tag after Mell review)

### Added

- Control Center charts **grid** (multi-metric), shared poll helpers, metrics cache, cursor sync, fleet host charts over SSH.
- Timeseries backend **downsample** + incremental tail (`max_points` / `after_ts`).
- Perimeter: **per-source** `port_scan_suspected`, `public_ports`, `inbound_flood_suspected`; TG Shield warn on public ports.
- Rootkit `deleted_exe` downgrade to info after package upgrade (`audit.deleted_exe_downgrade_on_upgrade`).
- `guard-core/` Rust crate: alert `schema_version`, procfs metrics/flow helpers, golden fixture.
- ML feature-event JSONL + weak labels (including Telegram ban/kill/isolate/mute/allow/host_fp) and the mini reference dataset (`docs/ML.md`).
- Per-rule adaptive thresholds (`ml.adaptive_thresholds`); critical severity is never softened.
- Model shadow/live/previous promote + rollback (`ml.shadow_dir`, `ml.live_dir`), verified with the supply-chain manifest before promote.
- `guard-core` CLI: `metrics`, `auth-fail-ip`, `tcp-addr`, `render`, `serve` (Unix JSONL IPC with live **RuleEngine**, **decide_risk**, helper **ban**). Defaults `use_for_rules` / `use_for_risk` on; Python fallback if socket down.
- Agent optional `onnx` feature (`tract-onnx`, not default): `--onnx-model` / `--onnx-shadow` attach `ml_score` extras.
- Timeseries metrics: `ml_raw_score`, `baseline_z`, `threshold`, severity-split alert rates.
- Charts grid overlays (risk+threshold, score+ml_raw, mem+swap, net/disk pairs), stacked severity alerts, marker → Alerts.
- Model-occlusion explain (`model_based_explain`); one-class ML mode default; shared Charts/Dashboards poller.
- Docs: `EBPF_SETUP.md` refresh, `NFT_COEXISTENCE.md`, `ML.md`.

### Changed

- Default `runtime.prefer: onnx` (falls back without artifacts); `ml.mode: one_class`; `ml.adaptive_thresholds: true`.
- Matplotlib alert panels debounced/cached off the hot path.
- Release musl agent build enables **eBPF by default**; visible `mode=proc` fallback.
- systemd agent unit: CAP_BPF/PERFMON/SYS_RESOURCE/SYS_PTRACE, `MemoryDenyWriteExecute=no`.
- Telegram long-poll exponential backoff on API failures; weak-label rate-limit + audit JSONL.
- `scan_unique_ports` replaces per-port unique-IP scan (`scan_unique_ips` deprecated alias).
- `find_bin` prefers bundled guard-core over PATH; optional `bin_sha256` pin; metrics swap throttled.

### Fixed

- Non-UTF8 `/proc/*/comm` no longer crashes perimeter mapping.
- Timeseries flush on disk-full no longer kills the sample loop (bounded buffer + backpressure).
- Collect daemon isolates `on_sample` failures.
- `alerts_per_min` only increments on emitted host alerts (after cooldown), not every anomalous tick.

### Known limitations

- Agent ONNX (`tract-onnx`) is feature-gated and off by default; scores are extras only and do not replace rule severity.

### Added (carried from unreleased 1.4.x line)

- Phase 7 ML honesty: leak-free train/val/test (+ gap), lab filters/balance opt-in, `ml.baselines`, gate vs best baseline, `docs/DATASET.md`, `collect_labeled` scaffold.
- Phase 7.5–7.9: `user_metrics` (FP/day, TTD), plain ML explain, FP suppress after «normal», drift refit controller, ONNX↔torch parity test.
- `backend_from_config` factory so CLI/friend/helper ban paths share ssh_port / egress / `allow_private_bans`.
- IPv6 brute aggregation can ban a `/48`–`/128` prefix via `ban6` `flags interval,timeout`.

### Changed (carried)

- `build-dataset` defaults: no lab filters, no balance; `eval_offline` hard-errors on `windows_format=scaled`; `check_ml_ready` requires fuse > best baseline (PR-AUC + recall@FPR1%).
- Auth Failed/Invalid: sshd end-of-line peer IP when unique; multiple `from <ip> port` → `auth_log_injection` (no ban). Accepted still uses the first `from`.
- FlowWatcher counts unique SYN_RECV peers; SYN_SENT is `flow_syn_sent_hang` (never ban-capable); reads `/proc/net/tcp6`.
- Login/unlock rate buckets are separate; login code rotates after repeated fails; correct fresh code bypasses 429 for wrong guesses.
- Mini App: negative group `chat_id` without `allowed_user_ids` → 403.
- Helper `ban.add` honors `allow_private_bans` and refuses Telegram/resolver/gateway like Python.

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
- Spoofed SYN_RECV no longer auto-bans Telegram/DNS/gateway/LAN: `ban_ip` refuses those, `flow.auto_ban` defaults off, RFC1918/ULA/CGNAT need `allow_private_bans`.
- Mini App auth no longer treats `lstrip("-")` of a group chat id as a user id; IPv6 SSH fails aggregate on `/64` and ban that prefix; auth injection via invalid-user name is detected.
- IPv6 default gateway is protected; resolv stub falls back to `/run/systemd/resolve/resolv.conf`.
- SSE sets `close_connection` after logout; auto-ban does not escalate TTL while the IP is still in the set; private auto-ban skip says `refuse private`.
- Telegram bot respects `telegram.allowed_user_ids` from config (not only env).
- `home health` does not treat a host with no journal files as an ssh source, including root (`journalctl` without `-q`).
- A second lockdown inserts a new admin allow before the SYN drop. syn-rate-limit does the same for its allow rules, and replaces the drop when rate/burst change.
- Kirk isolate keeps IPv6 resolvers from `resolvectl dns` and opens TCP/UDP 853 when the resolver is DNS-over-TLS (`#name`).
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

## [1.4.1] - 2026-11-20

### Security

- Agent clean shutdown requires an HMAC-signed stop marker; forged `si_pid` (e.g. via `rt_sigqueueinfo`) no longer retires the phoenix watchdog silently.
- Trusted pidfiles verify starttime/exe (agent/watchdog) or python `sysspectogram … guard` cmdline + uid (guard); foreign live PIDs are rejected.
- eBPF kill events carry sender `comm`/`ppid` at probe time; known setuid helpers (`sudo`/`su`/…) demote to low; X11/ICE/`/run/user` openat noise filtered.

### Fixed

- Root-watch exact-exe allowlist, baseline persist across respawn, cron/timer demotion, cmdline-aware dedup.
- Protect sessions/host inside v6 prefix bans; ban6 interval migration; helper v6 prefixes.
- Auth log injection rate-limit; login code rotation DoS; flow port-scan inbound + v4-mapped unwrap.
- Python root-watch fallback when agent is down; viz alert window samples; `backend_from_config` everywhere.
- Absolute `--guard-pidfile` / `--watchdog-pidfile`; phoenix respawn keeps them and `--root-allow`.
- Day0 GitHub API 403 messaging; refuse empty `--ip` for seed-never-ban.
- CI builds the agent with the eBPF object and `clippy -D warnings`.

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
