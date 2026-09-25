# SysSpectogram roadmap (v0.4+)

Status: **v0.4 ready to tag** — fuse, packs, lite/full, FIM, flow lite, **eBPF execve/openat** (clang BPF + Aya load; attach needs root).

## Shipped

- [x] Userspace agent + TG console unlock + web unlock gate
- [x] Fuse host+agent → `risk` score (`ensemble.host_weight` / `agent_weight`)
- [x] Profile packs pack/pull/install (`docs/PROFILES.md`)
- [x] Load profiles `lite` (small VPS) / `full` (large VDS)
- [x] Ops: agent systemd unit, `scripts/install.sh`, musl helper
- [x] FIM sha256 (`agent --fim`, enabled in `full` profile)
- [x] Socket same-uid harden (soft when PEERCRED unavailable) + 0600
- [x] Flow lite from `/proc/net/tcp` (enabled in `full`)
- [x] Aya-loaded eBPF probes (`execve`, `openat`) via clang BPF object — needs root to attach
- [ ] True XDP/TC flow counters (current flow is userspace heuristic)
- [ ] Full aya-ebpf Rust probes (blocked on Arch by rustc/bpf-linker LLVM mismatch; C+Aya works)

## Release checklist (v0.4.0)

1. Commit all v0.4 sources (exclude `.env`, `agent/target/`, local `artifacts/`).
2. Tag `v0.4.0`.
3. Upload Release assets from `dist/`:
   - `profile-generic-linux-v1.tar.gz`
   - `profile-generic-linux-v1.tar.gz.sha256`
4. Optional: also attach a prebuilt `sysspectogram-agent` binary for your arch (or document `cargo build --release`).

## Suggested next

1. Lab collect recipes per role (nginx/docker/3x-ui) to seed more packs
2. XDP/TC flow counters
3. Guard auto_start under systemd as root for eBPF mode by default on `full`
