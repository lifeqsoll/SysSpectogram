#!/usr/bin/env bash
# Headless day-0: wheel + venv + menu (no git clone).
#
# ALWAYS use a *tagged* raw URL (never floating main):
#   curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/v1.1.1/scripts/friend-day0.sh | bash -s -- v1.1.1
#
# Or download friend-day0.sh from the GitHub Release assets and run locally.
# Requires: curl, python3-venv, sha256sum, minisign (signatures are mandatory).
#
# Env: SYSSPECTOGRAM_GITHUB_REPO (default lifeqsoll/SysSpectogram)
#      SYSSPECTOGRAM_HOME (default ~/.local/share/sysspectogram)
set -euo pipefail

TAG="${1:-v1.1.1}"
[[ "${TAG}" == v* ]] || TAG="v${TAG}"
REPO="${SYSSPECTOGRAM_GITHUB_REPO:-lifeqsoll/SysSpectogram}"
HOME_DIR="${SYSSPECTOGRAM_HOME:-${HOME}/.local/share/sysspectogram}"
UA="SysSpectogram-FriendDay0/1.1"
API="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"

# Embedded minisign pubkey (same as Control Center bootstrap / ADR 0005).
MINISIGN_PUB_B64='RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need curl
need python3
need sha256sum
need minisign
python3 -c "import venv" 2>/dev/null || { echo "need python3-venv" >&2; exit 1; }

mkdir -p "${HOME_DIR}/state/bootstrap-cache"
export SYSSPECTOGRAM_HOME="${HOME_DIR}"

echo "==> release ${TAG} (${REPO})"
JSON="$(curl -fsSL -H "User-Agent: ${UA}" -H "Accept: application/vnd.github+json" "${API}")"
mapfile -t URLS < <(REL_JSON="${JSON}" python3 -c '
import json, os, sys
rel = json.loads(os.environ["REL_JSON"])
assets = {a["name"]: a["browser_download_url"] for a in (rel.get("assets") or [])}
wheel = next((n for n in assets if n.endswith(".whl")), None)
if not wheel:
    sys.exit("no .whl on release")
if "SHA256SUMS" not in assets:
    sys.exit("release missing SHA256SUMS")
agent = "sysspectogram-agent-x86_64-linux-musl"
if agent not in assets or f"{agent}.sha256" not in assets:
    sys.exit("release missing musl agent or .sha256")
wsig = f"{wheel}.minisig"
asig = f"{agent}.minisig"
if wsig not in assets:
    sys.exit(f"release missing {wsig} (minisign required for friend day0)")
if asig not in assets:
    sys.exit(f"release missing {asig} (minisign required for friend day0)")
print(assets[wheel])
print(wheel)
print(assets["SHA256SUMS"])
print(assets[agent])
print(assets[f"{agent}.sha256"])
print(assets[wsig])
print(assets[asig])
')

WHEEL_URL="${URLS[0]}"
WHEEL_NAME="${URLS[1]}"
SUMS_URL="${URLS[2]}"
AGENT_URL="${URLS[3]}"
AGENT_SUM_URL="${URLS[4]}"
WHEEL_SIG_URL="${URLS[5]}"
AGENT_SIG_URL="${URLS[6]}"
WHEEL_PATH="${HOME_DIR}/state/bootstrap-cache/${WHEEL_NAME}"
SUMS_PATH="${HOME_DIR}/state/bootstrap-cache/SHA256SUMS"
AGENT_PATH="${HOME_DIR}/state/bootstrap-cache/sysspectogram-agent-x86_64-linux-musl"
AGENT_SUM_PATH="${HOME_DIR}/state/bootstrap-cache/agent.sha256"
WHEEL_SIG_PATH="${WHEEL_PATH}.minisig"
AGENT_SIG_PATH="${AGENT_PATH}.minisig"
PUB_PATH="${HOME_DIR}/state/bootstrap-cache/SysSpectogram.minisign.pub"

{
  echo "untrusted comment: minisign public key: SysSpectogram"
  echo "${MINISIGN_PUB_B64}"
} > "${PUB_PATH}"

echo "==> download ${WHEEL_NAME} + SHA256SUMS + agent + minisig"
curl -fsSL -H "User-Agent: ${UA}" -o "${WHEEL_PATH}" "${WHEEL_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${SUMS_PATH}" "${SUMS_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${AGENT_PATH}" "${AGENT_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${AGENT_SUM_PATH}" "${AGENT_SUM_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${WHEEL_SIG_PATH}" "${WHEEL_SIG_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${AGENT_SIG_PATH}" "${AGENT_SIG_URL}"

EXP="$(awk -v n="${WHEEL_NAME}" '$0 ~ n {print tolower($1); exit}' "${SUMS_PATH}")"
GOT="$(sha256sum "${WHEEL_PATH}" | awk '{print $1}')"
if [[ -z "${EXP}" || "${EXP}" != "${GOT}" ]]; then
  echo "sha256 wheel mismatch: ${GOT} != ${EXP}" >&2
  exit 1
fi
echo "==> sha256 wheel ok"

AEXP="$(awk '{print tolower($1); exit}' "${AGENT_SUM_PATH}")"
AGOT="$(sha256sum "${AGENT_PATH}" | awk '{print $1}')"
if [[ -z "${AEXP}" || "${AEXP}" != "${AGOT}" ]]; then
  echo "sha256 agent mismatch: ${AGOT} != ${AEXP}" >&2
  exit 1
fi
echo "==> sha256 agent ok"

echo "==> minisign verify"
minisign -Vm "${WHEEL_PATH}" -p "${PUB_PATH}" -x "${WHEEL_SIG_PATH}"
minisign -Vm "${AGENT_PATH}" -p "${PUB_PATH}" -x "${AGENT_SIG_PATH}"
echo "==> minisign ok"

VENV="${HOME_DIR}/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "==> venv ${VENV}"
  python3 -m venv "${VENV}"
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"
pip install -q --upgrade pip
pip install -q --force-reinstall "${WHEEL_PATH}"

AGENT_DIR="${HOME_DIR}/bin"
mkdir -p "${AGENT_DIR}"
cp -f "${AGENT_PATH}" "${AGENT_DIR}/sysspectogram-agent"
chmod +x "${AGENT_DIR}/sysspectogram-agent"
echo "==> agent -> ${AGENT_DIR}/sysspectogram-agent"

if command -v loginctl >/dev/null 2>&1; then
  if ! loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
    echo '==> tip: loginctl enable-linger $USER   # else protect dies on SSH logout'
  fi
fi

echo "==> ready. SYSSPECTOGRAM_HOME=${HOME_DIR}"
echo "    ${VENV}/bin/python -m sysspectogram menu"
exec "${VENV}/bin/python" -m sysspectogram menu
