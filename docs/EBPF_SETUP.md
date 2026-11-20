# eBPF setup — Aya loader + clang BPF probes

Probes include `sys_enter_execve`, `sys_enter_openat`, `sys_enter_kill`, setuid helpers, and module load/unload.
Build: **system `clang -target bpf`**. Load/attach: **Aya** in `sysspectogram-agent`.

Needs **BTF** (`ls /sys/kernel/btf/vmlinux`) and **real root** (tracefs is typically `0700`).

## Arch

```bash
sudo pacman -S --needed base-devel rustup clang llvm libbpf
rustup default stable
cd agent && cargo build --release
```

## Debian 13 / Ubuntu 24.04

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev linux-libc-dev
# Without this, probes.c fails with 'asm/types.h not found'
export C_INCLUDE_PATH=/usr/include/$(uname -m)-linux-gnu
cd agent && cargo build --release
```

## Build notes

```bash
cd agent
cargo build --release
# binary: agent/target/release/sysspectogram-agent
```

Skip BPF compile (userspace-only): `SYSSPECTOGRAM_SKIP_EBPF=1 cargo build --release --no-default-features`

**Release musl agent** (GitHub assets) is built `--no-default-features` → **no eBPF**. Kill witness and eBPF setuid/openat alerts need a source build with the default `ebpf` feature. Packaged units that pass `--mode ebpf` require that binary; otherwise the agent falls back to userspace.

## Run (needs **real root**, not only setcap)

`/sys/kernel/tracing` is typically `0700 root`. Aya must `readdir` it to attach.
`setcap cap_bpf,...` is **not enough** → `tracefs not found` / not readable.

```bash
sudo -E ./agent/target/release/sysspectogram-agent \
  --mode ebpf \
  --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock" \
  --metrics-ms 1000
```

## Common errors

| Symptom | Fix |
|---|---|
| `asm/types.h not found` | Set `C_INCLUDE_PATH=/usr/include/$(uname -m)-linux-gnu` (Debian/Ubuntu) |
| `tracefs not readable` / not found | Run as root; do not rely on setcap alone |
| `BTF missing` | Install a kernel with BTF / ensure `/sys/kernel/btf/vmlinux` exists |

## Guard

```yaml
agent:
  mode: ebpf
```

```bash
sudo -E .venv/bin/python -m sysspectogram guard --telegram --dry-run
```

## Profile packs (GitHub Release)

```bash
mkdir -p dist
python -m sysspectogram profiles pack \
  --name profile-generic-linux-v1 --role generic-linux \
  --host artifacts/real_v3 \
  --out dist/profile-generic-linux-v1.tar.gz \
  --agent-if artifacts/agent_iforest.ssf.npz
```
