# SysSpectogram roadmap

Single forward plan. Goal: credible, honest, installable Linux VPS / host defense —
not a “rootkit killer” marketing claim.

**Status:** **v0.6** shipped (agent auth + self-protect + root watch in Rust + Role Lab + feedback).  
**Next:** v0.7 depth (FP / flow / UX). **Ceiling:** optional VMI in v1.0 ([VMI.md](VMI.md)).

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
v0.7  next        Depth: FP control, flow, response UX, pack polish
v0.8  harden      Supply chain (minisign/cosign), SBOM, distro-ready packaging
v1.0  ceiling     Optional VMI (self-host KVM only)
v1.x  ecosystem   AUR/deb, Prometheus, community packs, EN/RU Day-0
```

---

## Shipped — v0.6 baseline

| Area | What |
| --- | --- |
| Agent auth | HMAC-SHA256 on critical rules; PEERCRED fail-closed; PID allowlist; exe seal |
| Self-protect | Phoenix watchdog, CLEAN_SHUTDOWN, Dead-man, `agent_exe_mismatch` |
| Root watch | Unexpected uid=0 in Rust `ProcWatcher` (same `/proc` walk); TG Kill |
| Sessions | Unexpected SSH after learn → Kick tty / Ban IP |
| Role Lab | Collect/train/pack roles without KVM (`role-lab`) |
| Feedback | TG Ignore / As normal / As anomaly → learner + optional retrain |
| Packs | HMAC `.sig` verify (`pack_sign`); `validate-pack` |
| OSINT | Score/dossier helpers ([OSINT.md](OSINT.md)) |
| Docs / ops | DAY0_VPS, AGENT_PROTECT, SECURITY.md, CI workflows |

Docs: [AGENT.md](AGENT.md) · [AGENT_PROTECT.md](AGENT_PROTECT.md) · [ROOT_WATCH.md](ROOT_WATCH.md) · [ROLE_LAB.md](ROLE_LAB.md) · [FEEDBACK.md](FEEDBACK.md) · [DAY0_VPS.md](DAY0_VPS.md)

---

## Why trust is often `best-effort`

Many Arch/cloud hosts: Secure Boot off, no `CONFIG_IMA`, TPM alone ≠ measured boot.
**Measured** = readable IMA **and** (SB on or TPM). Correct label, not a bug.
Cloud VPS ceiling is often best-effort until VMI (host) in v1.0.

---

## v0.7 — Make it *deeper* (next)

Theme: quieter alerts, richer signals, clearer ops — without blowing lite VPS budget.

| Track | Work | Why |
| --- | --- | --- |
| A | Role pack FP pass (ssh/nginx/docker/panel) + TG digests | Kill alert fatigue |
| B | Better flow (XDP/TC or cheaper netview) where practical | Replace `/proc` net heuristic |
| C | Response UX: isolate/release confirm audit log; web kirk badge | Operator confidence |
| D | Agent IF / feedback retrain one-shot on builder | Close the learn loop |
| E | Optional eBPF assist for root/setuid (fallback stays ProcWatcher) | Lower latency, same lite cost when idle |
| F | Cold-install checklist on real clean VPS (operator-run) | Prove Day-0 |

**Exit:** quiet ssh VPS &lt; 10 TG alerts/day after tune; full profile clearly better than lite on 4 vCPU.

---

## v0.8 — Make it *harder to subvert* (supply chain)

| Track | Work |
| --- | --- |
| A | minisign/cosign on release artifacts (beyond pack HMAC) |
| B | SBOM + Dependabot; refuse unsigned weights on VPS by default |
| C | Distro packaging sketch (AUR / deb) with CAP_BPF notes |
| D | Prefer non-pickle model export docs; joblib quarantine |

**Exit:** documented supply chain; local same-UID forge path stays mitigated (already HMAC+PID+seal).

---

## v1.0 — Optional ceiling (VMI)

| Track | Work |
| --- | --- |
| A | `sysspectogram-vmi` on KVM/libvirt — guest RAM vs agent |
| B | Trust `out-of-band` only when VMI channel healthy |
| C | Explicit matrix: cloud max vs HV self-host |

Skip if no HV users. Do not block OSS value. See [VMI.md](VMI.md).

---

## v1.x — Ecosystem

- AUR / deb with clear caps
- Prometheus / OTel exporter
- Opt-in SIEM webhook; no phone-home
- Community pack registry (sha256 + maintainer)
- Keep Day-0 EN/RU

---

## Will not chase early

- Windows / macOS agents
- “Rootkit-proof” claims
- Bundling exploit/rootkit samples
- Forcing Torch on 1 GB VPS
- VMI required for basic value

---

## Near-term backlog (ordered)

1. Tag **v0.6.0** + GitHub Release notes ([RELEASE_v0.6.0.md](RELEASE_v0.6.0.md)).
2. Operator cold install on clean VPS; fix Day-0 gaps found.
3. Role pack FP pass + TG digests.
4. Feedback retrain polish on builder.
5. Flow / net depth for full profile.
6. minisign release artifacts.
7. VMI only with a real KVM lab user.

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

*Last updated: 2026-09-26*
