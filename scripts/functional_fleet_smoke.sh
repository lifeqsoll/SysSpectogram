#!/usr/bin/env bash
# Local functional smoke (not unit tests): fleet store, profiles, graph, warmup, unlock help, CLI wiring.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${ROOT}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3)"
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export XDG_CONFIG_HOME="$TMP/config"
export XDG_STATE_HOME="$TMP/state"
FLEET="$XDG_CONFIG_HOME/sysspectogram/fleet.json"
mkdir -p "$XDG_CONFIG_HOME/sysspectogram" "$XDG_STATE_HOME/sysspectogram/state"

SS="$PY -m sysspectogram"
fail=0
ok() { echo "OK  $*"; }
bad() { echo "FAIL $*"; fail=$((fail + 1)); }

echo "=== fleet path / add / primary / list ==="
$SS fleet path | grep -q '"ok": true' || bad "fleet path"
$SS fleet add --id web1 --label "Web 1" --ssh user@web1 --home /opt/ss --role primary --device-token tok1
$SS fleet add --id worker1 --label "Worker" --ssh user@w1 --home /opt/ss --role worker --tags api
$SS fleet add --id bastion --label "Bastion" --ssh user@bast --role bastion
$SS fleet primary --id web1 | grep -q '"primary_host_id": "web1"' || bad "primary"
LIST="$($SS fleet list)"
echo "$LIST" | grep -q '"id": "web1"' || bad "list web1"
echo "$LIST" | grep -q '\*\*\*' || bad "token redacted"
# re-add without token must preserve previous token
$SS fleet add --id web1 --label "Web 1b" --ssh user@web1 --role primary
$PY - <<PY || bad "token preserved on re-add"
import json
from pathlib import Path
raw = json.loads(Path("$FLEET").read_text())
h = next(x for x in raw["hosts"] if x["id"] == "web1")
assert h.get("device_token") == "tok1", h
assert h.get("label") == "Web 1b"
print("token_preserved")
PY

echo "=== profiles / groups / edges / graph ==="
$SS fleet profile-set --id soft --label Soft \
  --settings '{"response.mode":"observe","response.never_ban_cidrs":"10.0.0.0/8"}' \
  | grep -q '"ok": true' || bad "profile-set"
BAD_OUT="$($SS fleet profile-set --id bad --settings '{"response.mode":"isolate"}' || true)"
echo "$BAD_OUT" | grep -q '"ok": false' || bad "profile isolate rejected"
$SS fleet group-set --id prod --label Prod --hosts web1,worker1 --profile-id soft \
  | grep -q '"ok": true' || bad "group-set"
$SS fleet edge-add --from web1 --to worker1 --kind depends_on --note "api" \
  | grep -q '"ok": true' || bad "edge-add"
GRAPH="$($SS fleet graph)"
echo "$GRAPH" | grep -q '"from": "web1"' || bad "graph edge"
echo "$GRAPH" | grep -q '"worker1"' || bad "graph dependents"

echo "=== warmup local ==="
# seed never_ban + fake labels for ready_for_shield
STATE_DIR="$($PY -c 'from sysspectogram.config import state_root; print(state_root())')"
mkdir -p "$STATE_DIR/state"
printf '%s\n' '{"response.never_ban_cidrs":"127.0.0.1/32","response.mode":"observe"}' \
  >"$STATE_DIR/state/user-settings.json"
printf '%s\n' '[{"exe":"/bin/true","label":"ok"},{"exe":"/bin/false","label":"bad"},{"exe":"/usr/bin/ssh","label":"ok"}]' \
  >"$STATE_DIR/state/process_labels.json"
WARM="$($SS home warmup)"
echo "$WARM" | grep -q '"ok": true' || bad "home warmup"
echo "$WARM" | grep -q '"ready_for_shield": true' || bad "ready_for_shield"
$SS fleet warmup --scope local | grep -q '"ready_for_shield": true' || bad "fleet warmup local"

echo "=== home settings allowlist ==="
$SS home settings --changes '{"response.mode":"observe"}' | grep -q '"ok": true' || bad "home settings"
$SS home settings --changes '{"not.allowed":1}' | grep -q '"rejected"' || bad "settings reject"

echo "=== unlock / LOCKED playbook ==="
$PY - <<'PY' || bad "locked_playbook"
from sysspectogram.unlock_help import locked_playbook
t = locked_playbook(host_id="web1", lang="en")
assert "UNLOCK" in t.upper() or "unlock" in t.lower() or "SSH" in t
assert "web1" in t or "host" in t.lower()
print("playbook_ok")
PY

echo "=== store dependents (bastion not auto via role filter in attack) ==="
$PY - <<PY || bad "dependents"
from pathlib import Path
from sysspectogram.fleet.store import FleetStore
st = FleetStore(Path("$FLEET"))
deps = st.dependents("web1")
assert "worker1" in deps, deps
print("deps", deps)
PY

echo "=== CLI help surfaces ==="
$SS fleet --help | grep -q profile-apply || bad "help profile-apply"
$SS fleet --help | grep -q edge-add || bad "help edge-add"
$SS home --help | grep -q warmup || bad "help home warmup"

echo "=== quarantine dry-run (no nft apply) ==="
$PY - <<'PY' || bad "quarantine dry-run"
from sysspectogram.response.actions import NftBackend
nft = NftBackend()
msg = nft.quarantine_ports([80, 443], dry_run=True, ttl_sec=60)
assert "dry-run" in str(msg).lower(), msg
msg2 = nft.release_quarantine(dry_run=True)
assert "dry" in str(msg2).lower() or msg2 is not None
print("quarantine", msg, "release", msg2)
PY

echo "=== protect status (best-effort, may be inactive) ==="
$SS protect status >/dev/null || true
ok "protect status invoked"

if [[ "$fail" -eq 0 ]]; then
  echo "ALL FUNCTIONAL SMOKE PASSED"
  exit 0
fi
echo "FAILED checks: $fail"
exit 1
