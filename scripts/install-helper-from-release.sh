#!/usr/bin/env bash
# Install privileged helper from a GitHub Release (no local git / cargo).
#
# Prefer the signed release asset (raw.githubusercontent skips .minisig — do not use it):
#   TAG=v1.3.3
#   curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh"
#   curl -fsSL -O "https://github.com/lifeqsoll/SysSpectogram/releases/download/${TAG}/install-helper-from-release.sh.minisig"
#   minisign -Vm install-helper-from-release.sh -P 'RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'
#   sudo bash install-helper-from-release.sh "$TAG"
#
# Requires: curl, sha256sum, install, systemctl, minisign, python3, tar
# Env: SYSSPECTOGRAM_DEV=1 + SYSSPECTOGRAM_GITHUB_REPO to allow a non-default repo
set -euo pipefail

TAG="${1:-v1.3.3}"
[[ "${TAG}" == v* ]] || TAG="v${TAG}"

REPO="lifeqsoll/SysSpectogram"
if [[ -n "${SYSSPECTOGRAM_GITHUB_REPO:-}" ]]; then
  if [[ "${SYSSPECTOGRAM_DEV:-}" != "1" ]]; then
    echo "refusing SYSSPECTOGRAM_GITHUB_REPO without SYSSPECTOGRAM_DEV=1" >&2
    exit 1
  fi
  echo "WARNING: SYSSPECTOGRAM_DEV=1 using alternate repo ${SYSSPECTOGRAM_GITHUB_REPO}" >&2
  REPO="${SYSSPECTOGRAM_GITHUB_REPO}"
fi

UA="SysSpectogram-HelperInstall/1.2"
API="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"

# Embedded minisign pubkey (same as friend-day0 / Control Center / ADR 0005).
MINISIGN_PUB_B64='RWQpTS7f641bPCuKPgJc2mbA/oBkH2Yen4gN1JTofbwvyfbS6yYmLD8F'

INSTALL_TEST="${SYSSPECTOGRAM_HELPER_INSTALL_TEST:-}"

if [[ "${EUID}" -ne 0 ]]; then
  if [[ "${INSTALL_TEST}" != "1" ]]; then
    echo "run as root: sudo $0 ${TAG}" >&2
    exit 1
  fi
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
need curl
need sha256sum
need install
need systemctl
need minisign
need python3
need tar

WORKDIR="$(mktemp -d)"
chmod 700 "${WORKDIR}"
trap 'rm -rf "${WORKDIR}"' EXIT

PUB_PATH="${WORKDIR}/SysSpectogram.minisign.pub"
{
  echo "untrusted comment: minisign public key: SysSpectogram"
  echo "${MINISIGN_PUB_B64}"
} > "${PUB_PATH}"

asset_url() {
  local want="$1"
  REL_JSON="${JSON}" WANT="${want}" python3 -c '
import json, os, sys
rel = json.loads(os.environ["REL_JSON"])
want = os.environ["WANT"]
for a in rel.get("assets") or []:
    if a.get("name") == want:
        print(a["browser_download_url"]); break
else:
    sys.exit("no asset on release: " + want)
'
}

echo "==> release ${TAG}"
JSON="$(curl -fsSL -H "User-Agent: ${UA}" -H "Accept: application/vnd.github+json" "${API}")"

BIN_NAME="sysspectogram-helper-x86_64-linux"
PACK_NAME="sysspectogram-helper-packaging.tgz"
BIN_URL="$(asset_url "${BIN_NAME}")"
BIN_SIG_URL="$(asset_url "${BIN_NAME}.minisig")"
SUM_URL="$(asset_url "${BIN_NAME}.sha256")"
PACK_URL="$(asset_url "${PACK_NAME}")"
PACK_SIG_URL="$(asset_url "${PACK_NAME}.minisig")"

BIN="${WORKDIR}/${BIN_NAME}"
BIN_SIG="${BIN}.minisig"
SUM_FILE="${WORKDIR}/helper.sha256"
PACK_TGZ="${WORKDIR}/${PACK_NAME}"
PACK_SIG="${PACK_TGZ}.minisig"

echo "==> download helper + signatures + packaging.tgz"
curl -fsSL -H "User-Agent: ${UA}" -o "${BIN}" "${BIN_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${BIN_SIG}" "${BIN_SIG_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${SUM_FILE}" "${SUM_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${PACK_TGZ}" "${PACK_URL}"
curl -fsSL -H "User-Agent: ${UA}" -o "${PACK_SIG}" "${PACK_SIG_URL}"
chmod 0755 "${BIN}"

EXP="$(awk '{print tolower($1)}' "${SUM_FILE}" | head -1)"
GOT="$(sha256sum "${BIN}" | awk '{print $1}')"
if [[ -z "${EXP}" || "${EXP}" != "${GOT}" ]]; then
  echo "sha256 mismatch: ${GOT} != ${EXP}" >&2
  exit 1
fi
echo "==> sha256 ok"

refuse_downgrade() {
  local want="$1" have="$2"
  [[ -z "${have}" ]] && return 0
  WANT="${want}" HAVE="${have}" python3 -c '
import os, sys
def tup(v):
    return tuple(int("".join(c for c in x if c.isdigit()) or "0") for x in v.strip().lstrip("v").split("."))
w, h = tup(os.environ["WANT"]), tup(os.environ["HAVE"])
sys.exit(0 if w >= h else 1)
'
}

verify_minisign_asset() {
  local file="$1" sig="$2" asset_name="$3"
  local out tc want installed
  if ! out="$(minisign -Vm "${file}" -p "${PUB_PATH}" -x "${sig}" 2>&1)"; then
    echo "${out}" >&2
    exit 1
  fi
  tc=""
  while IFS= read -r line; do
    if [[ "${line}" == Trusted\ comment:* ]]; then
      tc="${line#Trusted comment:}"
      tc="${tc#"${tc%%[![:space:]]*}"}"
    fi
  done <<< "${out}"
  want="sysspectogram ${TAG} ${asset_name}"
  if [[ -z "${tc}" || "${tc}" != "${want}" ]]; then
    echo "minisign trusted comment mismatch: got '${tc}', want '${want}'" >&2
    exit 1
  fi
  installed=""
  if [[ -f /etc/sysspectogram/helper-release-tag ]]; then
    installed="$(tr -d '[:space:]' < /etc/sysspectogram/helper-release-tag)"
  elif [[ -n "${SYSSPECTOGRAM_INSTALLED_HELPER_TAG:-}" ]]; then
    installed="${SYSSPECTOGRAM_INSTALLED_HELPER_TAG}"
  fi
  if [[ -n "${installed}" ]] && ! refuse_downgrade "${TAG}" "${installed}"; then
    echo "refuse helper downgrade: installed ${installed}, requested ${TAG}" >&2
    exit 1
  fi
}

echo "==> minisign verify"
verify_minisign_asset "${BIN}" "${BIN_SIG}" "${BIN_NAME}"
verify_minisign_asset "${PACK_TGZ}" "${PACK_SIG}" "${PACK_NAME}"
echo "==> minisign ok"

if [[ "${INSTALL_TEST}" == "1" ]]; then
  echo "verify-only ok (tag ${TAG})"
  exit 0
fi

PACK_DIR="${WORKDIR}/pack"
mkdir -m 700 "${PACK_DIR}"

# Refuse absolute paths, .., and symlinks before extract.
python3 - "${PACK_TGZ}" "${PACK_DIR}" <<'PY'
import sys, tarfile
from pathlib import Path

tgz, dest = sys.argv[1], Path(sys.argv[2])
allowed = {
    "packaging/helper/sysspectogram-helper.service",
    "packaging/helper/sysusers.conf",
    "packaging/polkit/org.sysspectogram.helper.policy",
    "scripts/install-helper-from-release.sh",
}
with tarfile.open(tgz, "r:gz") as tf:
    members = []
    for m in tf.getmembers():
        name = m.name.lstrip("./")
        if not name or name.endswith("/"):
            continue
        if name.startswith("/") or ".." in Path(name).parts:
            sys.exit(f"refusing unsafe tar entry: {m.name}")
        if m.issym() or m.islnk():
            sys.exit(f"refusing link in packaging.tgz: {m.name}")
        if not m.isfile():
            sys.exit(f"refusing non-file in packaging.tgz: {m.name}")
        if name not in allowed:
            sys.exit(f"unexpected packaging entry: {name}")
        m.name = name
        members.append(m)
    for m in members:
        out = dest / m.name
        out.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            sys.exit(f"cannot extract {m.name}")
        data = src.read()
        out.write_bytes(data)
        out.chmod(0o644)
PY

UNIT="${PACK_DIR}/packaging/helper/sysspectogram-helper.service"
POLICY="${PACK_DIR}/packaging/polkit/org.sysspectogram.helper.policy"
SYSUSERS="${PACK_DIR}/packaging/helper/sysusers.conf"
if [[ ! -f "${UNIT}" || ! -f "${POLICY}" || ! -f "${SYSUSERS}" ]]; then
  echo "packaging.tgz missing unit/policy/sysusers" >&2
  exit 1
fi

install -d -m 0755 /etc/sysspectogram /opt/sysspectogram /var/lib/sysspectogram \
  /usr/lib/sysspectogram /usr/share/sysspectogram
install -Dm755 "${BIN}" /usr/lib/sysspectogram/sysspectogram-helper
install -Dm644 "${UNIT}" /etc/systemd/system/sysspectogram-helper.service
install -Dm644 "${POLICY}" /usr/share/polkit-1/actions/org.sysspectogram.helper.policy
install -Dm644 "${SYSUSERS}" /usr/lib/sysusers.d/sysspectogram.conf
install -Dm644 "${PUB_PATH}" /usr/share/sysspectogram/minisign.pub

if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers /usr/lib/sysusers.d/sysspectogram.conf
fi
systemctl daemon-reload
systemctl enable sysspectogram-helper.service
systemctl restart sysspectogram-helper.service

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  usermod -aG sysspectogram "${SUDO_USER}" || true
  echo "added ${SUDO_USER} to group sysspectogram — log out/in (or reboot) so the group sticks;"
  echo "  Start/Restart still asks for an admin password via polkit (desktop agent required)."
fi

install -Dm644 /dev/stdin /etc/sysspectogram/helper-release-tag <<< "${TAG}"
systemctl --no-pager --full status sysspectogram-helper.service || true
echo "helper socket: /run/sysspectogram/helper.sock"
echo "minisign.pub: /usr/share/sysspectogram/minisign.pub"
echo "done (tag ${TAG})"
