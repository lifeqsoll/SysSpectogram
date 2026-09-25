# SysSpectogram roadmap (v0.5+)

Status: **v0.5** — VPS Adopt + in-guest Kirk + honest IMA/SB/TPM trust labels.

**Forward plan (quality OSS):** [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md)

## Shipped in v0.5

- [x] Fuse risk, packs, lite/full, FIM, flow lite, console unlock
- [x] eBPF execve/openat/module (clang BPF + Aya; needs root)
- [x] runtime `notorch` | `onnx` | `torch_ml`
- [x] train bridge (`data bundle` / `artifacts push`)
- [x] `response.mode` observe|shield|aggressive
- [x] kirk_isolate / kirk_release API (+ TTL)
- [x] Cross-view + kallsyms presence baseline
- [x] IMA / Secure Boot / TPM trust probe (`kirk trust`)
- [x] auto_isolate on CRITICAL kirk (config, default off)

## Explicitly deferred

| Item | When | Why |
| --- | --- | --- |
| **VMI binary** | **v1.0** | Hypervisor only — [VMI.md](VMI.md) |
| Full aya-ebpf Rust probes | later | LLVM mismatch; C+Aya works |
| XDP/TC flow | v0.7 | current flow is `/proc` heuristic |

## Next (v0.6)

See [ROADMAP_QUALITY.md](ROADMAP_QUALITY.md): release hygiene, CI, FP control, Day-0 docs, trust reason codes.
