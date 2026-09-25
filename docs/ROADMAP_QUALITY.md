# SysSpectogram — quality open-source defense roadmap

Goal: become a **credible, honest, installable** Linux host / VPS defense tool that operators trust — not a “rootkit killer” marketing claim.

Status after **v0.5**: perimeter + agent + ONNX path + Kirk best-effort + trust labels. This document is the **forward plan**.

---

## Why your box is `best-effort` (IMA / Secure Boot)

Probe on this host (Arch `7.2.6-arch2-1`):

| Signal | State | Why |
| --- | --- | --- |
| **EFI** | yes | Machine boots UEFI |
| **Secure Boot** | **off** | EFI var `SecureBoot-…` data byte = `0`. Typical on Arch: custom/DKMS modules, unsigned kernels, or never enabled in firmware |
| **IMA** | **absent** | Stock Arch kernel: `# CONFIG_IMA is not set` — no `/sys/kernel/security/ima` at all |
| **TPM** | present | `/dev/tpm0` exists — useful later for attestation; alone ≠ measured boot |

**Measured** in SysSpectogram means: *readable IMA measurements* **and** (Secure Boot on **or** TPM). Without IMA in the kernel, we correctly stay **best-effort**. That is honesty, not a bug.

### How an operator *could* reach `measured`

1. **Secure Boot on** — firmware setup → enable SB; on Arch this usually means signed kernel/modules (or enroll MOK). Painful with nvidia/DKMS.
2. **IMA** — needs a kernel built with `CONFIG_IMA` (and usually a policy). Distros that often ship it: some Ubuntu/Fedora/RHEL images. Arch stock = no.
3. Cloud VPS: many providers disable SB and omit IMA; **best-effort is the realistic ceiling** there until VMI (host) in v1.0.

Docs: [KIRK.md](KIRK.md), [VMI.md](VMI.md).

---

## Product principles (non‑negotiable)

1. **Honest trust labels** — never claim measured/out-of-band without evidence.
2. **Safe defaults** — observe / dry-run; `auto_isolate` off; unlock gates destructive TG.
3. **VPS-first install** — `notorch` / ONNX day-0; Torch only on builder.
4. **No malware / rootkit samples in repo** — lab checklists only.
5. **Reproducible packs** — sha256, signed releases, CI.
6. **Small surface** — prefer fewer sharp tools that work over a kitchen sink.

---

## Phase map

```text
v0.5  shipped     Adopt + Kirk best-effort + trust probe
v0.6  quality     Reliability, packs, docs, FP control, CI
v0.7  depth       Role packs, better eBPF/flow, response UX
v0.8  hardenin    Artifact signing, agent auth, self-protect
v1.0  ceiling     Optional VMI (self-host KVM only)
v1.x  ecosystem   Distro packages, Grafana, threat intel hooks
```

---

## v0.6 — Make it *reliable* (next)

**Theme:** people can install once and leave it running without spam or surprise lockouts.

| Track | Work | Why |
| --- | --- | --- |
| A | Tag `v0.5.0`, GitHub Release + profile pack with `cnn.onnx` | Discoverability |
| B | CI: pytest + `cargo test` + clippy smoke; musl agent artifact | Trust in builds |
| C | Module learn window + TG digests (kirk module_load) | Kill alert fatigue |
| D | Role packs: ssh-only, nginx, docker, 3x-ui | Lower FP on real VPS |
| E | Install path: `bootstrap.sh` → systemd units root agent + user guard | “Just works” |
| F | Docs: one **Day-0 VPS** page (notorch → shield → unlock) | Adoption |
| G | `kirk trust` explains *why* (CONFIG_IMA unset / SB off) | Operator education |

**Exit:** random Arch/Debian VPS survives 7 days with useful alerts, no TG flood, no accidental isolate.

---

## v0.7 — Make it *deeper*

| Track | Work |
| --- | --- |
| A | XDP/TC or better flow (replace `/proc` heuristic where possible) |
| B | FIM + baseline polish; optional dm-verity *hint* if present |
| C | Response UX: TG buttons isolate/release/reboot-confirm; audit log |
| D | Agent IF retrain recipes per role; online calibration drift UX |
| E | Optional `ima_appraisal` *read-only* guidance doc (distro-specific) |
| F | Web dashboard: kirk trust badge, isolate state, agent heartbeat |

**Exit:** full profile on a 4 vCPU VDS is clearly better than lite; operators prefer SysSpectogram over raw fail2ban alone.

---

## v0.8 — Make it *hard to subvert*

| Track | Work |
| --- | --- |
| A | Agent → guard **HMAC / PID allowlist** for kirk CRITICAL (no socket forge) |
| B | Artifact push: signed manifest (minisign/cosign); refuse unsigned on VPS |
| C | Prefer non-pickle model export where practical; joblib quarantine docs |
| D | Agent self-protect: systemd watchdog, BPF attach missing alert, readonly config |
| E | Footprint / SBOM; dependabot; SECURITY.md + disclosure |

**Exit:** local same-UID malware cannot trivially auto-isolate; supply chain for weights is documented.

---

## v1.0 — Make the *ceiling* real (optional)

| Track | Work |
| --- | --- |
| A | `sysspectogram-vmi` on KVM/libvirt host — compare guest RAM vs agent |
| B | Trust label `out-of-band` only when VMI channel healthy |
| C | Explicit matrix: cloud VPS max = measured/best-effort; HV self-host = oob |

See [VMI.md](VMI.md). **Skip** if no HV users; do not block OSS usefulness.

---

## v1.x — Ecosystem (quality OSS community)

- Distro packaging (AUR / deb) with clear caps (CAP_BPF, CAP_NET_ADMIN)
- Prometheus/OpenTelemetry metrics exporter
- Optional webhook → SIEM; no cloud phone-home by default
- Community profile pack registry with sha256 + maintainer identity
- Threat-intel *opt-in* denylist feeds (never required)
- Translation: keep README + Day-0 in EN/RU

---

## What we will *not* chase early

- Windows / macOS agents
- Claiming “rootkit-proof”
- Bundling exploit/rootkit code for “tests”
- Forcing Torch on 1 GB VPS
- Shipping VMI as required for basic value

---

## Near-term backlog (concrete, ordered)

1. Finish v0.5 release hygiene (tag, pack+onnx, Day-0 doc).
2. Enrich `kirk trust` / `/status` with **reason codes** (`ima_not_in_kernel`, `secure_boot_off`, `tpm_ok`).
3. Module learn + digest; role pack FP pass.
4. CI + release binaries.
5. Agent↔guard auth for kirk actions.
6. Signed artifacts.
7. Revisit VMI only with a real KVM lab user.

---

## Success metrics

| Metric | Target |
| --- | --- |
| Fresh VPS time-to-first-useful-alert | &lt; 30 min with Day-0 doc |
| TG alerts/day on quiet ssh VPS | &lt; 10 after tune |
| False isolate incidents | 0 with defaults |
| Trust label accuracy | never claim measured without IMA+SB/TPM evidence |
| Stars/issues response | triage SECURITY in &lt; 72 h |

---

*Last updated: 2026-09-25*
