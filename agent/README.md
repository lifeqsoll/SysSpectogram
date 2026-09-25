# SysSpectogram agent (Rust)

See [docs/AGENT.md](../docs/AGENT.md), [docs/EBPF_SETUP.md](../docs/EBPF_SETUP.md), [docs/ROADMAP_V3.md](../docs/ROADMAP_V3.md).

```bash
cargo build --release
./target/release/sysspectogram-agent --help
# eBPF attach (needs root on Arch):
# sudo -E ./target/release/sysspectogram-agent --mode ebpf --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock"
```
