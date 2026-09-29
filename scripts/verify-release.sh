#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 PUBLIC_KEY FILE [FILE ...]" >&2
  exit 2
fi

PUBLIC_KEY="$1"
shift
command -v minisign >/dev/null || {
  echo "minisign is required" >&2
  exit 127
}
[[ -s "$PUBLIC_KEY" ]] || {
  echo "public key is missing: $PUBLIC_KEY" >&2
  exit 1
}

for asset in "$@"; do
  [[ -f "$asset" ]] || {
    echo "release asset is missing: $asset" >&2
    exit 1
  }
  signature="$asset.minisig"
  [[ -f "$signature" ]] || {
    echo "release signature is missing: $signature" >&2
    exit 1
  }
  minisign -Vm "$asset" -p "$PUBLIC_KEY" -x "$signature" -q
  printf 'verified %s\n' "$asset"
done
