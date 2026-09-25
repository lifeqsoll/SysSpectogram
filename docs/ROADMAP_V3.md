# SysSpectogram roadmap (v0.5+)

Status: **v0.5** — VPS Adopt (notorch/ONNX/bridge) + in-guest Kirk + **IMA/TPM/Secure Boot trust**.

## Shipped in v0.5

- [x] Fuse risk, packs, lite/full, FIM, flow lite, console unlock
- [x] eBPF execve/openat/module (clang BPF + Aya; needs root)
- [x] runtime `notorch` | `onnx` | `torch_ml`
- [x] train bridge (`data bundle` / `artifacts push`)
- [x] `response.mode` observe|shield|aggressive
- [x] kirk_isolate / kirk_release API
- [x] Cross-view module hide in agent loop
- [x] Baseline seal (`--kirk-seal`) + drift poll
- [x] IMA / Secure Boot / TPM **measured** trust (`kirk trust`, guard probe)
- [x] auto_isolate on CRITICAL kirk (config, default off)

## Explicitly deferred

| Item | When | Why |
| --- | --- | --- |
| **VMI binary** (`sysspectogram-vmi`) | **v1.0** | Needs hypervisor; cloud VPS N/A — see [VMI.md](VMI.md) |
| Full aya-ebpf Rust probes | later | LLVM mismatch on Arch; C+Aya works |
| XDP/TC flow | later | current flow is `/proc` heuristic |

## Release checklist (v0.5.0)

1. Profile pack with `cnn.onnx` when available.
2. Tag `v0.5.0`, upload `dist/profile-generic-linux-v1.tar.gz` + sha256.
3. Smoke: `kirk trust`, guard notorch/onnx, agent `sudo -E --mode ebpf`.
