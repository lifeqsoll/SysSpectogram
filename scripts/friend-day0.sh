#!/usr/bin/env bash
# Headless day-0: wheel + venv + menu (no git clone).
#
# One-liner (as the user that will own protect):
#   curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/scripts/friend-day0.sh | bash -s -- v1.1.0
#
# Env: SYSSPECTOGRAM_GITHUB_REPO (default lifeqsoll/SysSpectogram)
#      SYSSPECTOGRAM_HOME (default ~/.local/share/sysspectogram)
set -euo pipefail

TAG="${1:-v1.1.0}"
[[ "${TAG}" == v* ]] || TAG="v${TAG}"
REPO="${SYSSPECTOGRAM_GITHUB_REPO:-lifeqsoll/SysSpectogram}"
HOME_DIR="${SYSSPECTOGRAM_HOME:-${HOME}/.local/share/sysspectogram}"
UA="SysSpectogram-FriendDay0/1.1"
API="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need curl
need python3
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
print(assets[wheel])
print(wheel)
print(assets.get("sysspectogram-agent-x86_64-linux-musl", ""))
')

WHEEL_URL="${URLS[0]}"
WHEEL_NAME="${URLS[1]}"
AGENT_URL="${URLS[2]:-}"
WHEEL_PATH="${HOME_DIR}/state/bootstrap-cache/${WHEEL_NAME}"
echo "==> download ${WHEEL_NAME}"
curl -fsSL -H "User-Agent: ${UA}" -o "${WHEEL_PATH}" "${WHEEL_URL}"

VENV="${HOME_DIR}/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "==> venv ${VENV}"
  python3 -m venv "${VENV}"
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"
pip install -q --upgrade pip
pip install -q --force-reinstall "${WHEEL_PATH}"

if [[ -n "${AGENT_URL}" ]]; then
  AGENT_DIR="${HOME_DIR}/bin"
  mkdir -p "${AGENT_DIR}"
  curl -fsSL -H "User-Agent: ${UA}" -o "${AGENT_DIR}/sysspectogram-agent" "${AGENT_URL}"
  chmod +x "${AGENT_DIR}/sysspectogram-agent"
  echo "==> agent -> ${AGENT_DIR}/sysspectogram-agent"
fi

if command -v loginctl >/dev/null 2>&1; then
  if ! loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then
    echo '==> tip: loginctl enable-linger $USER   # else protect dies on SSH logout'
  fi
fi

echo "==> ready. SYSSPECTOGRAM_HOME=${HOME_DIR}"
echo "    ${VENV}/bin/python -m sysspectogram menu"
exec "${VENV}/bin/python" -m sysspectogram menu
