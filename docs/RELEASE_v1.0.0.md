# SysSpectogram v1.0.0 — Control Center, incidents, dashboards

v1.0 turns SysSpectogram from a set of CLI tools into a desktop product: a Control Center for protection, dashboards, lab runs and settings, backed by a small privileged helper. It also adds an incident engine, event-level scoring and a read-only VMI cross-view.

Status: code for every phase is in the repository. The automated test block ran on 2026-10-11 (results below). Remaining before the tag: the maintainer's visual check, the sudo install steps, and a decision on the model quality (see EVAL.md).

Product description (what the tool is, capabilities, limitations): [PRODUCT_v1.0.md](PRODUCT_v1.0.md).

## What changed

### Scoring and fusion (phase 0, 1)
- Alert gate: anomaly if host score ≥ host threshold **or** fused risk ≥ `ensemble.risk_threshold`. Documented in [adr/0001-fusion-gating.md](adr/0001-fusion-gating.md).
- Agent score decays with a half-life (`agent.score_half_life_sec`, default 60 s) instead of staying constant.
- Fusion weights are 0.6 / 0.4 in the config, training and docs. Host-vs-agent fusion uses the same weights.
- Agent features: per-channel event matrix (cap 20 per channel per second) replaces the single count. Training uses event timestamps, not wall-clock time.
- Event spectrogram CNN (`sysspectogram/agent_spectro.py`), ONNX export, opt-in with `agent.spectrogram: false` by default. See [adr/0002-event-spectrogram.md](adr/0002-event-spectrogram.md).

### Incident engine
- `python -m sysspectogram incidents list|show|report`.
- Normalizes alerts from `alerts.jsonl`, `agent.jsonl`, `perimeter.jsonl`, groups by shared entity (pid, comm, path, ip) within a 300 s window, and maps rules to ATT&CK techniques (best effort).
- Store `reports/incidents.jsonl` (`incident.v1`), atomic upsert.
- HTML report is self-contained and HTML-escaped; Markdown report too.

### VMI cross-view (read-only)
- `sysspectogram/vmi/`: task source interface, mock backend, cross-view with confirmation streak and one alert per hidden pid, libvmi backend.
- Off by default (`kirk.vmi: false`). Trust label `lab` on one machine ([adr/0003-trust-labels.md](adr/0003-trust-labels.md)).
- The libvmi backend is **not verified on hardware** (see known gaps). Details: [VMI.md](VMI.md).

### Privileged helper (`helper/`)
- Unix socket, JSON line protocol, allowlisted operations: `status`, `service`, `bundle.install`, `settings.apply`, `settings.rollback`.
- Caller identified with `SO_PEERCRED`; polkit check per mutating action (`org.sysspectogram.helper.service|bundle-install|settings`).
- Signed bundle install: manifest and signature copied to a root-owned staging area, `minisign` verification, sha256 for each file, then install with an atomic `current` link switch. See [adr/0004-privilege-helper-split.md](adr/0004-privilege-helper-split.md) and [adr/0005-signed-bundle-not-git.md](adr/0005-signed-bundle-not-git.md).
- Settings overlay `/etc/sysspectogram/settings.json`, merged by `config.py` at load time. One-step rollback.

### Control Center (`control-center/`)
- Tauri 2 (Rust core) + Svelte 5 + TypeScript, uPlot charts, handwritten SVG icons.
- Sidebar: Overview, Live, Dashboards (1 h, 6 h, 12 h, 24 h, 7 d, 30 d), Incidents, Agent, Perimeter, Settings, Scenarios, Tests and Lab, Install and Updates, Logs and Audit, About and Docs.
- English by default, Russian one click away. Setting texts come from `configs/schema.yaml`.
- Settings editor: validation, diff with explanations, restart hints, apply, rollback.
- Scenario presets (`configs/scenarios/`): `ssh-server-vps`, `web-server`, `workstation`, `lab-demo`, `hardened-observe`.
- Lab runs: registered, localhost-only, streamed output, check for the expected alert in the reports.
- Details and CLI parity table: [CONTROL_CENTER.md](CONTROL_CENTER.md).

### Timeseries store
- `state/timeseries.sqlite` (WAL): raw 1 s (1 h), 10 s (12 h), 1 min (7 d), 5 min (30 d). Written by the guard, read read-only by the UI.

### Packaging and versions
- Version 1.0.0 in `pyproject.toml`, `sysspectogram/__init__.py`, `agent/Cargo.toml` and `Cargo.lock`, `packaging/aur/PKGBUILD`, Debian changelog.
- Kernel module `sysspectogram_wd` keeps its own version (0.9.0); it has no changes in this release.
- Helper unit: `packaging/helper/sysspectogram-helper.service`, sysusers `packaging/helper/sysusers.conf`, polkit policy `packaging/polkit/org.sysspectogram.helper.policy`.

## Upgrade notes

- **Agent IF model file name** changed to `agent_iforest.ssf.npz` in profile packs. Retrain with `train-agent-if` or repack with `profiles pack --agent-if artifacts/agent_iforest.ssf.npz`.
- **Config** gained `timeseries`, `agent.score_half_life_sec`, `agent.spectrogram`, `agent.spectrogram_model`, `kirk.vmi*`, and `monitor.interval_sec` in `default.yaml`. Existing user configs keep working; missing keys fall back to defaults.
- **Fusion weights** are now 0.6 / 0.4 for host-vs-CNN/IF. If you tuned 0.55 / 0.45, set them again in your config.
- **Agent alerts** from a silent agent now decay to zero, so host-only risk is `0.6 × host`. Host-threshold alerts are unchanged.
- **Helper** writes `/etc/sysspectogram/settings.json`. Remove it to return to the YAML defaults.

## Verification plan (final test block)

Run in this order and record the results in this file:

1. `python -m pytest -q` (includes the new tests: `test_risk_gating`, `test_incident_correlator`, `test_vmi_crossview`, `test_timeseries_store`, `test_settings_schema`, `test_lab_runs`, `test_cli_parity`).
2. `python scripts/check_settings_i18n.py` and `python scripts/check_cli_parity.py`.
3. `cd agent && cargo check && cargo test` (the agent changed: pid snapshots and the `--pids-sec` flag).
4. `cd helper && cargo test && cargo build --release`.
5. `cd control-center && npm install && npm run check && npm test && npm run build`, then `npm run tauri build` once icons exist (see gaps).
6. FP/FN replay: `scripts/eval_offline.py` before and after the fusion change, results in [EVAL.md](EVAL.md).
7. Incident replay on `simulations/intrusion`, then `incidents report` for the resulting incident.
8. Visual check of the built binary by the maintainer.
9. Subagent security and bug review of the whole change set (requested by the maintainer), fixes, then the commit.

## Results (automated test block, 2026-10-11)

| Check | Result |
| --- | --- |
| `pytest -q` (in `.venv`) | 164 passed (one stale count fixed: scenarios now 10) |
| `scripts/check_settings_i18n.py` | settings=16 problems=0 |
| `scripts/check_cli_parity.py` | cli=29 documented=29 missing=0 extra=0 |
| `cd agent && cargo check && cargo test` | clean, 6 tests passed (one dead-code warning fixed) |
| `cd helper && cargo test && cargo build --release` | 4 tests passed, release build ok |
| `cd control-center && npm run check` | 0 errors, 0 warnings |
| `npm test` | 6 passed |
| `npm run build` and `npm run tauri build` | ok; AppImage and deb produced |
| `scripts/eval_offline.py` | ran; model methods do not separate the classes, see [EVAL.md](EVAL.md) |
| Incident replay on `simulations/intrusion` | not run in this pass (needs the guard and perimeter watcher running) |
| Visual check of the binary | maintainer, pending |

Not run by the assistant: any `sudo` step (see the list below), and the push.

## Known gaps (honest)

- **First-run download** of the matching release is not implemented. v1.0 installs a signed bundle from a local folder. The trust checks are in place, so a download step can be added on top.
- **Bundle content**: the bundle carries the agent binary and the manifest. The Python package and `configs/` are installed by the package manager (AUR, deb). Shipping `configs/schema.yaml` and `configs/scenarios/` as package data must be checked in the packaging test.
- **Settings change log** (`config_changes.jsonl`) is not implemented. Each apply keeps the previous overlay in `settings.json.bak`, and rollback swaps the two files.
- **libvmi backend** is not verified on hardware. The binding names are written against the Python API and must be checked on a KVM guest. Until then keep `kirk.vmi_backend: mock`.
- **Event spectrogram CNN** (`agent.spectrogram`) is not proven better yet. It stays off until the offline replay shows a gain.
- **Control Center** compiles in release mode (`npm run tauri build` built the binary). Icons are generated in `control-center/src-tauri/icons/`. The visual check of the binary is still pending.
- **Incident web tab** was not added. The Control Center Incidents screen covers the same data; the legacy `web` dashboard is unchanged.
- **Helper** has unit tests for parsing and validation only. The polkit path is tested only on the target machine.
- **Agent socket window**: the listener starts before the agent's PID allowlist and exe seal are set. Until then, a process running as the guard's user could send datagrams. The window is short with the guard-spawned agent. The fix (drop datagrams until the binding exists) needs a check on the external systemd layout first, so it is not in v1.0.
- **Agent and guard users** in the distro units may differ (the agent unit can run as root while the guard runs as `sysspectogram` with `require_same_uid`). Check the pairing on the target machine before relying on agent alerts.

## System steps (sudo, run by the maintainer)

These change the system and are not run by the repository tooling.

1. Enable virtualization in BIOS/UEFI (SVM for AMD, VT-x for Intel). Check with `lscpu | grep -i virtualization`.
2. Install the virtualization stack: `sudo pacman -S qemu-desktop libvirt`, then libvmi and its Python binding from the AUR.
3. Load KVM: `sudo modprobe kvm_amd` (or `kvm_intel`). Check `ls -l /dev/kvm`.
4. Enable libvirt and add your user to the groups: `sudo systemctl enable --now libvirtd`, `sudo usermod -aG libvirt,kvm $USER`, then log out and in.
5. eBPF smoke test as root (the agent needs `CAP_BPF` and `CAP_PERFMON`): `sudo -E agent/target/release/sysspectogram-agent --mode ebpf --help`, then a short run as in [EBPF_SETUP.md](EBPF_SETUP.md).
6. Install the agent binary root-owned: `sudo install -o root -g root -m 0755 agent/target/release/sysspectogram-agent /usr/local/sbin/`.
7. Install the helper with one script (builds nothing, copies the binary, unit, polkit policy and sysusers entry, then starts the service): `cd helper && cargo build --release && cd .. && sudo scripts/install-helper.sh`. It also adds the invoking user to group `sysspectogram`; log out and back in afterwards.
   - `sudo usermod -aG sysspectogram $USER` (then log out and in)
8. Install the public signing key used to verify bundles: `sudo install -Dm644 sysspectogram.minisign.pub /usr/share/sysspectogram/minisign.pub`, and `sudo pacman -S minisign`.
9. Install the guard unit from the package (`packaging/distro/sysspectogram-guard.service`) if it is not installed yet.
10. Control Center build dependencies (Tauri 2 on Arch): `sudo pacman -S webkit2gtk-4.1 base-devel curl wget file openssl librsvg`.

## Release assets

Attach these files to the GitHub Release for v1.0.0:

- `sysspectogram-control-center` (the release binary, built by `npm run tauri build` in `control-center/`; copy it from `control-center/src-tauri/target/release/`)
- `SysSpectogram Control Center_1.0.0_amd64.AppImage` and `SysSpectogram Control Center_1.0.0_amd64.deb` (from `control-center/src-tauri/target/release/bundle/`, names may differ slightly)
- `SHA256SUMS` made with `sha256sum sysspectogram-control-center *.AppImage *.deb > SHA256SUMS`

The binary needs the Python package installed (see the Control Center section of the README) to run the CLI actions. The helper and agent binaries are built with `cargo build --release` and are not part of the UI bundle.

## Tag and release (maintainer)

The maintainer makes the commit, the tag and the push:

```bash
git add -A
git commit -m "v1.0.0: Control Center, helper, incidents, dashboards, VMI cross-view"
git tag -a v1.0.0 -m "SysSpectogram v1.0.0"
git push origin main --follow-tags
```

Then create the GitHub Release from this file.
