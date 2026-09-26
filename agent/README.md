# SysSpectogram agent (Rust)

See [docs/AGENT.md](../docs/AGENT.md), [docs/ROOT_WATCH.md](../docs/ROOT_WATCH.md), [docs/AGENT_PROTECT.md](../docs/AGENT_PROTECT.md), [docs/ROADMAP_QUALITY.md](../docs/ROADMAP_QUALITY.md).

```bash
cargo build --release
./target/release/sysspectogram-agent --help
# eBPF attach (needs root on Arch):
# sudo -E ./target/release/sysspectogram-agent --mode ebpf --socket "$XDG_RUNTIME_DIR/sysspectogram-agent.sock"
```
