#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 PUBLIC_KEY FILE [FILE ...]" >&2
  echo "  optional: VERIFY_RELEASE_TAG=<tag> checks minisign trusted comment" >&2
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

VERIFY_RELEASE_TAG="${VERIFY_RELEASE_TAG:-}"

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
  out="$(minisign -Vm "$asset" -p "$PUBLIC_KEY" -x "$signature" 2>&1)"
  if [[ -n "$VERIFY_RELEASE_TAG" ]]; then
    tc=""
    while IFS= read -r line; do
      if [[ "$line" == Trusted\ comment:* ]]; then
        tc="${line#Trusted comment:}"
        tc="${tc#"${tc%%[![:space:]]*}"}"
      fi
    done <<< "$out"
    want="sysspectogram ${VERIFY_RELEASE_TAG} $(basename "$asset")"
    if [[ -z "$tc" || "$tc" != "$want" ]]; then
      echo "minisign trusted comment mismatch for $(basename "$asset"): got '${tc}', want '${want}'" >&2
      exit 1
    fi
  fi
  printf 'verified %s\n' "$asset"
done
