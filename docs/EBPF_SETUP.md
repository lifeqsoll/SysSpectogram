# eBPF setup (Arch) — Aya loader + clang BPF probes

Probes: `sys_enter_execve`, `sys_enter_openat`  
Build: **system `clang -target bpf`** (avoids rustc/bpf-linker LLVM mismatch on Arch).  
Load/attach: **Aya** in `sysspectogram-agent`.

## Already done on this machine

- `clang` / `llvm` / `libbpf`
- BTF: `/sys/kernel/btf/vmlinux`
- Agent builds BPF object into `OUT_DIR/sysspectogram-ebpf`

## Build

```bash
cd agent
cargo build --release
# binary: agent/target/release/sysspectogram-agent
```

Skip BPF compile (userspace-only): `SYSSPECTOGRAM_SKIP_EBPF=1 cargo build --release --no-default-features`

## Run (needs **real root**, not only setcap)

On Arch, `/sys/kernel/tracing` is typically `0700 root`. Aya must `readdir` it to attach.
`setcap cap_bpf,...` is **not enough** → you get `tracefs not found` / not readable.

```bash
# correct
sudo -E ./agent/target/release/sysspectogram-agent \
  --mode ebpf \
  --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock" \
  --metrics-ms 1000
```

## Guard

```yaml
# configs/default.yaml or full load profile
agent:
  mode: ebpf
```

```bash
# guard still auto_starts agent; run guard as root OR pre-start agent with caps
sudo -E .venv/bin/python -m sysspectogram guard --model artifacts/real_v3 --telegram --dry-run
```

Alerts: `agent_ebpf_execve`, `agent_ebpf_openat` (plus existing userspace rules).

## Profile packs (GitHub Release)

```bash
mkdir -p dist
python -m sysspectogram profiles pack \
  --name profile-generic-linux-v1 --role generic-linux \
  --host artifacts/real_v3 \
  --out dist/profile-generic-linux-v1.tar.gz \
  --agent-if artifacts/agent_iforest.joblib
# upload dist/*.tar.gz + *.sha256 to GitHub Release v0.4.0
```

Pull example after publish:

```bash
python -m sysspectogram profiles pull \
  --url https://github.com/<org>/SysSpectogram/releases/download/v0.4.0/profile-generic-linux-v1.tar.gz \
  --out /tmp/p.tar.gz \
  --sha256 "$(cut -d' ' -f1 dist/profile-generic-linux-v1.tar.gz.sha256)"
```
