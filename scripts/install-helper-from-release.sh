#!/usr/bin/env bash
# Install privileged helper from a GitHub Release (no local git / cargo).
#
# Friend one-liner:
#   curl -fsSL https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/scripts/install-helper-from-release.sh | sudo bash -s -- v1.1.0
#
# Or after download:
#   sudo bash install-helper-from-release.sh v1.1.0
#
# Env: SYSSPECTOGRAM_GITHUB_REPO (default lifeqsoll/SysSpectogram)
set -euo pipefail

TAG="${1:-v1.1.0}"
[[ "${TAG}" == v* ]] || TAG="v${TAG}"
REPO="${SYSSPECTOGRAM_GITHUB_REPO:-lifeqsoll/SysSpectogram}"
UA="SysSpectogram-HelperInstall/1.1"
API="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
RAW="https://raw.githubusercontent.com/${REPO}/${TAG}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0 ${TAG}" >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need curl
need sha256sum
need install
need systemctl

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "==> release ${TAG}"
JSON="$(curl -fsSL -H "User-Agent: ${UA}" -H "Accept: application/vnd.github+json" "${API}")"
BIN_URL="$(REL_JSON="${JSON}" TAG="${TAG}" python3 -c '
import json, os, sys
rel = json.loads(os.environ["REL_JSON"])
want = "sysspectogram-helper-x86_64-linux"
for a in rel.get("assets") or []:
    if a.get("name") == want:
        print(a["browser_download_url"]); break
else:
    sys.exit("no helper binary on release " + os.environ.get("TAG", ""))
')"
SUM_URL="$(REL_JSON="${JSON}" python3 -c '
import json, os
rel = json.loads(os.environ["REL_JSON"])
want = "sysspectogram-helper-x86_64-linux.sha256"
for a in rel.get("assets") or []:
    if a.get("name") == want:
        print(a["browser_download_url"]); break
' || true)"

BIN="${WORKDIR}/sysspectogram-helper"
echo "==> download helper"
curl -fsSL -H "User-Agent: ${UA}" -o "${BIN}" "${BIN_URL}"
chmod +x "${BIN}"

if [[ -n "${SUM_URL:-}" ]]; then
  SUM_FILE="${WORKDIR}/helper.sha256"
  curl -fsSL -H "User-Agent: ${UA}" -o "${SUM_FILE}" "${SUM_URL}"
  EXP="$(awk '{print tolower($1)}' "${SUM_FILE}" | head -1)"
  GOT="$(sha256sum "${BIN}" | awk '{print $1}')"
  if [[ -n "${EXP}" && "${EXP}" != "${GOT}" ]]; then
    echo "sha256 mismatch: ${GOT} != ${EXP}" >&2
    exit 1
  fi
  echo "==> sha256 ok"
fi

UNIT="${WORKDIR}/sysspectogram-helper.service"
POLICY="${WORKDIR}/org.sysspectogram.helper.policy"
SYSUSERS="${WORKDIR}/sysusers.conf"
echo "==> packaging from ${RAW}"
curl -fsSL -H "User-Agent: ${UA}" -o "${UNIT}" "${RAW}/packaging/helper/sysspectogram-helper.service"
curl -fsSL -H "User-Agent: ${UA}" -o "${POLICY}" "${RAW}/packaging/polkit/org.sysspectogram.helper.policy"
curl -fsSL -H "User-Agent: ${UA}" -o "${SYSUSERS}" "${RAW}/packaging/helper/sysusers.conf"

install -d -m 0755 /etc/sysspectogram /opt/sysspectogram /var/lib/sysspectogram /usr/lib/sysspectogram
install -Dm755 "${BIN}" /usr/lib/sysspectogram/sysspectogram-helper
install -Dm644 "${UNIT}" /etc/systemd/system/sysspectogram-helper.service
install -Dm644 "${POLICY}" /usr/share/polkit-1/actions/org.sysspectogram.helper.policy
install -Dm644 "${SYSUSERS}" /usr/lib/sysusers.d/sysspectogram.conf

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/sysspectogram.conf
fi
systemctl daemon-reload
systemctl enable sysspectogram-helper.service
systemctl restart sysspectogram-helper.service

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  usermod -aG sysspectogram "${SUDO_USER}" || true
  echo "added ${SUDO_USER} to group sysspectogram — log out/in before Control Center"
fi

systemctl --no-pager --full status sysspectogram-helper.service || true
echo "helper socket: /run/sysspectogram/helper.sock"
echo "done (tag ${TAG})"
