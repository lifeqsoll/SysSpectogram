# SysSpectogram roadmap

Single forward plan. Goal: credible, honest, installable Linux VPS / host defense —
not a “rootkit killer” marketing claim.

**Status:** **v0.8** complete (supply-chain signatures, SBOM, packages, and model
loading policy). **Ceiling:** optional VMI in v1.0 ([VMI.md](VMI.md)).

---

## Product principles

1. Honest trust labels — never claim `measured` / out-of-band without evidence.
2. Safe defaults — observe / dry-run; `auto_isolate` off; unlock gates destructive TG.
3. VPS-first — `notorch` / ONNX day-0; Torch only on builder.
4. No malware / rootkit samples in repo.
5. Reproducible packs — sha256, HMAC `.sig`, CI artifacts.
6. Small surface — fewer sharp tools that work.

---

## Phase map

```text
v0.5  shipped     Adopt + Kirk best-effort + trust probe
v0.6  shipped     Auth, self-protect, agent root watch, Role Lab, feedback, CI
v0.7  shipping    Configure TUI, ProcessLabelRules, FP digests, netview, audit, eBPF setuid
v0.8  shipped     Supply chain (minisign), SBOM, distro-ready packaging, model quarantine
v1.0  ceiling     Optional VMI (self-host KVM only)
v1.x  ecosystem   AUR/deb, Prometheus, community packs, EN/RU Day-0
```

---

## Shipped — v0.7

| Track | What |
| --- | --- |
| Killer | `sysspectogram configure` + host_probe + override confirms |
| A | Role FP label seeds + richer TG `/digest` + `/labels` |
| B | Flow `netview` (`ss`) with `/proc` fallback |
| C | `response_audit.jsonl`; lockdown confirm path; web kirk badge |
| D | ProcessLabelRules; opt-in IF refit; builder `feedback retrain` kept |
| E | eBPF setuid/setreuid/setresuid→0 assist; ProcWatcher fallback |
| F | [COLD_INSTALL.md](COLD_INSTALL.md) + `--accept-recommended` |

Docs: [CONFIGURE.md](CONFIGURE.md) · [FEEDBACK.md](FEEDBACK.md) · [COLD_INSTALL.md](COLD_INSTALL.md) · [RELEASE_v0.7.0.md](RELEASE_v0.7.0.md)

---

## Shipped — v0.6 baseline

| Area | What |
| --- | --- |
| Agent auth | HMAC-SHA256 on critical rules; PEERCRED fail-closed; PID allowlist; exe seal |
| Self-protect | Phoenix watchdog, CLEAN_SHUTDOWN, Dead-man, `agent_exe_mismatch` |
| Root watch | Unexpected uid=0 in Rust `ProcWatcher`; TG Kill |
| Sessions | Unexpected SSH after learn → Kick tty / Ban IP |
| Role Lab | Collect/train/pack roles without KVM (`role-lab`) |
| Feedback | TG Ignore / As normal / As anomaly → learner + optional retrain |
| Packs | HMAC `.sig` verify (`pack_sign`); `validate-pack` |
| OSINT | Score/dossier helpers ([OSINT.md](OSINT.md)) |

---

## Why trust is often `best-effort`

Many Arch/cloud hosts: Secure Boot off, no `CONFIG_IMA`, TPM alone ≠ measured boot.
**Measured** = readable IMA **and** (SB on or TPM). Correct label, not a bug.
Cloud VPS ceiling is often best-effort until VMI (host) in v1.0.

---

## Shipped — v0.8 — Make it *harder to subvert* (supply chain)

| Track | Work |
| --- | --- |
| A | minisign signatures on release binaries, wheels, SBOM, and profile packs; HMAC remains compatible |
| B | Deterministic SPDX 2.3 SBOM, dependency audit, and opt-in refusal of unsigned model manifests |
| C | Buildable AUR / Debian package recipes with hardened units and CAP_BPF notes |
| D | Safe `weights_only` checkpoint loading, ONNX-first VPS docs, and joblib quarantine behind verification |

Evidence and operator procedures: [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) and
[RELEASE_v0.8.0.md](RELEASE_v0.8.0.md).

---

## v1.0 — Optional ceiling (VMI)

See [VMI.md](VMI.md). Skip if no HV users.

---

## Will not chase early

- Windows / macOS agents
- “Rootkit-proof” claims
- Bundling exploit/rootkit samples
- Forcing Torch on 1 GB VPS
- VMI required for basic value
- CNN fine-tune on 1 GB VPS / Rust CNN training

---

## Success metrics

| Metric | Target |
| --- | --- |
| Fresh VPS time-to-first-useful-alert | &lt; 30 min (Day-0) |
| TG alerts/day on quiet ssh VPS | &lt; 10 after tune |
| False isolate with defaults | 0 |
| Trust label accuracy | never claim measured without evidence |
| SECURITY triage | &lt; 72 h |

---

*Last updated: 2026-09-27*
