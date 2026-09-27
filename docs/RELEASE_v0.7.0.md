# SysSpectogram v0.7.0 — Deeper ops on the VPS

Release after v0.6 agent harden: **Day-0 configure**, quieter false positives via
**ProcessLabelRules**, richer digests/audit, cheaper flow, optional IF refit —
without forcing CNN fine-tune on a 1 GB box.

## Why it matters

| Before (v0.6) | Now (v0.7) |
| --- | --- |
| Day-0 = edit YAML + thin `setup` for `.env` | **`configure` TUI** + host_probe recommendations; overrides need confirm |
| As normal / As anomaly = bias + vague retrain | **ProcessLabelRules** (exact / prefix / glob / …) + `/labels`; role FP seeds |
| Full CNN retrain expected somehow on VPS | **Rules first**; optional **IF-only refit**; CNN stays builder-only |
| Flow = `/proc/net/tcp` only | **netview** (`ss`) + `/proc` fallback on full profile |
| Destructive TG actions hard to audit | **`reports/response_audit.jsonl`** |
| Kirk trust only in console/TG | **Web kirk badge** on live dashboard |
| Root = ProcWatcher poll | + **eBPF setuid→0 assist** (`agent_ebpf_setuid_root`); ProcWatcher remains fallback |
| Cold install tribal knowledge | **[COLD_INSTALL.md](COLD_INSTALL.md)** checklist |

**Honest limits:** labels do not replace a good host model; IF refit is opt-in and still not a full detector rewrite; eBPF setuid needs root/`CAP_BPF` and quiet hosts (desktop flood remains a reason to prefer `userspace`). Trust stays `best-effort` without IMA+SB/TPM.

## What's new

### Configure (killer Day-0)

- `python -m sysspectogram configure` — Rich terminal UI (not a browser)
- `host_probe`: RAM / vCPU / container / desktop / onnx|torch → recommend `lite`/`full`, agent, flow, `runtime.prefer`, feedback knobs
- Changing away from recommendation shows a warning + `y/N`
- `--accept-recommended --role ssh` for scripted / cold VPS
- Writes deep-merged `configs/default.yaml`, `.env`, `state/host_probe.json`
- Optional role FP seed into `state/process_labels.json`

Docs: [CONFIGURE.md](CONFIGURE.md) · [COLD_INSTALL.md](COLD_INSTALL.md)

### ProcessLabelRules + feedback loop

- Store: `state/process_labels.json` (v2). Legacy `operator_feedback.json` migrates.
- Match: `exact`, `comm_prefix`, `comm_regex`, `path_glob`, `path_contains`, `cmdline_contains`
- Priority: **anomaly > ignore > baseline**
- TG: As normal / As anomaly / **+ similar**, `/labels`, `/label-del`
- CLI: `labels list|seed|del`
- Role seeds: ssh / nginx / docker / panel / python / wireguard ([role_fp](../sysspectogram/role_fp.py))
- Global threshold bias via `FeedbackLearner` kept
- Optional: `feedback.if_refit: true` → debounced / CLI `feedback retrain-if` (CNN/ONNX untouched)
- Builder full retrain: `feedback retrain` (Torch) unchanged

Docs: [FEEDBACK.md](FEEDBACK.md) · [TELEGRAM.md](TELEGRAM.md)

### Flow / netview (Track B)

```yaml
flow:
  enabled: true          # full preset
  backend: netview       # proc | netview | both
  window_sec: 30
  syn_threshold: 80
  unique_port_threshold: 40
```

Lite keeps flow off / `proc` by default.

### Response UX (Track C)

- Append-only `reports/response_audit.jsonl` (no secrets in payload)
- Lockdown / isolate still go through unlock + confirm tokens
- Live web: **kirk trust badge** + isolated flag ([web static](../sysspectogram/web/static/))

### eBPF setuid assist (Track E)

- Probes: `setuid` / `setreuid` / `setresuid` toward uid 0 from non-root
- Alert id: `agent_ebpf_setuid_root`
- Lite / no-eBPF: **ProcWatcher `root_watch`** still authoritative

Docs: [EBPF_SETUP.md](EBPF_SETUP.md) · [ROOT_WATCH.md](ROOT_WATCH.md)

### Digests / ops polish (Track A)

- `/digest` includes alerts_today, response_mode, kirk trust, feedback bias/counts, label count, last IF refit
- Version bump: package + agent **0.7.0**

## Quick start

```bash
pip install -e ".[onnx]"   # or .[dev] / .[ml] on builder
cd agent && cargo build --release && cd ..

python -m sysspectogram configure --accept-recommended --role ssh
# or interactive:
# python -m sysspectogram configure

python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
# console prints UNLOCK CODE → TG: /unlock NNNNNN
# /labels  /digest  As normal / + similar
```

Optional IF refit (after enough labeled windows):

```bash
python -m sysspectogram feedback retrain-if --model artifacts/real_v3
```

## Config knobs (new / important)

```yaml
load_profile: lite   # or full — configure / probe picks this
runtime:
  prefer: notorch    # torch only if probe says so
agent:
  enabled: true
  auto_start: true
  mode: userspace    # ebpf on quiet VPS with root
  root_watch: true
flow:
  enabled: false
  backend: proc      # netview on full
feedback:
  if_refit: false
  widen_rules: comm_prefix   # false | comm_prefix | path_glob | both
response:
  mode: observe
telegram:
  require_console_unlock: true
```

## Docs

- [CONFIGURE.md](CONFIGURE.md) · [COLD_INSTALL.md](COLD_INSTALL.md) · [FEEDBACK.md](FEEDBACK.md)
- [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md) — v0.7 shipping; next v0.8 supply chain
- [RELEASE_v0.6.0.md](RELEASE_v0.6.0.md) — prior agent harden release
- README EN/RU updated for configure Day-0

## Upgrade notes

1. `pip install -e '.[onnx]'` (or reinstall) — `__version__` → **0.7.0**.
2. Rebuild agent (`cargo build --release`) for setuid probes + prior root_watch.
3. Run `configure` once (or merge YAML knobs above by hand).
4. Old `state/operator_feedback.json` → labels migrate on first guard/labels load.
5. Prefer `agent.mode: userspace` on desktop; `ebpf` on quiet VPS as root.
6. Keep `--dry-run` / `response.mode: observe` until unlock + labels are trusted.
7. Do **not** expect CNN fine-tune on 1 GB VPS — use labels + optional IF; full retrain on a builder PC.

## Not in 0.7

- CNN fine-tune on VPS / Rust CNN training
- minisign / cosign / SBOM (v0.8)
- Live VMI (v1.0)
