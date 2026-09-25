#!/usr/bin/env bash
# Optional static-ish agent build for older VDS (musl).
set -euo pipefail
cd "$(dirname "$0")/../agent"
rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
cargo build --release --target x86_64-unknown-linux-musl
echo "binary: target/x86_64-unknown-linux-musl/release/sysspectogram-agent"
