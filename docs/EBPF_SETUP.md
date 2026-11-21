# eBPF setup — Aya loader + clang BPF probes

Probes: `sys_enter_execve`, `sys_enter_openat`, `sys_enter_kill`, setuid helpers, module load/unload.
Build: system `clang -target bpf`. Load/attach: **Aya** in `sysspectogram-agent`.

Requirements:

| Check | Minimum |
|---|---|
| Kernel | ≥ 5.8 (CAP_BPF / ring buffer) |
| BTF | `/sys/kernel/btf/vmlinux` present (`CONFIG_DEBUG_INFO_BTF`) |
| Caps / user | root **or** `CAP_BPF` + `CAP_PERFMON` **and** readable tracefs |
| Tracefs | `/sys/kernel/tracing` (often mode `0700` → real root needed) |
| Lockdown | not integrity/confidentiality blocking BPF |

At startup the agent prints `eBPF probe: available=…` and either attaches or falls back:

```text
mode=ebpf
mode=proc (ebpf unavailable: <reason>)
```

Fallback is **visible** (stderr + effective mode). The process does not exit.

## Arch

```bash
sudo pacman -S --needed base-devel rustup clang llvm libbpf
rustup default stable
cd agent && cargo build --release
```

## Debian 13 / Ubuntu 24.04

```bash
sudo apt-get update
sudo apt-get install -y build-essential clang llvm libbpf-dev linux-libc-dev musl-tools
export C_INCLUDE_PATH=/usr/include/$(uname -m)-linux-gnu
cd agent && cargo build --release
```

## Musl static (release shape)

```bash
rustup target add x86_64-unknown-linux-musl
cd agent
C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
```

Default features include `ebpf`. Userspace-only:

```bash
SYSSPECTOGRAM_SKIP_EBPF=1 cargo build --release --no-default-features
```

GitHub `release-assets` builds the musl agent **with eBPF enabled** (clang/llvm/libbpf + musl-gcc).

## Run

```bash
sudo -E ./agent/target/release/sysspectogram-agent \
  --mode ebpf \
  --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock" \
  --metrics-ms 1000
```

`setcap` alone is often **not enough** if `/sys/kernel/tracing` is `0700`.

## systemd

`packaging/sysspectogram-agent.service` grants:

`CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE` and `MemoryDenyWriteExecute=no`.

## Common errors

| Symptom | Fix |
|---|---|
| `asm/types.h not found` | `C_INCLUDE_PATH=/usr/include/$(uname -m)-linux-gnu` |
| `tracefs not readable` | run as root |
| `BTF missing` | kernel with BTF / install `linux-image-…` debug BTF package |
| `mode=proc (ebpf unavailable: …)` | expected fallback — check reason string |

## Guard config

```yaml
agent:
  mode: ebpf
```

```bash
sudo -E .venv/bin/python -m sysspectogram guard --telegram --dry-run
```
