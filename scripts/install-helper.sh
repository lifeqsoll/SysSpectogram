#!/usr/bin/env bash
# Install the SysSpectogram privileged helper as a systemd service.
#
# Run once, as root, after building the helper:
#   cd helper && cargo build --release && cd ..
#   sudo scripts/install-helper.sh
#
# The user who runs `sudo` is added to the `sysspectogram` group, so the Control
# Center can reach the helper socket. Log out and back in after the first install.
# Every mutating action is still checked by polkit.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "run as root: sudo $0 [path/to/sysspectogram-helper]" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-${ROOT}/helper/target/release/sysspectogram-helper}"
if [[ ! -x "${BIN}" ]]; then
    echo "helper binary not found or not executable: ${BIN}" >&2
    echo "build it first: cd helper && cargo build --release" >&2
    exit 1
fi

UNIT_SRC="${ROOT}/packaging/helper/sysspectogram-helper.service"
if [[ ! -f "${UNIT_SRC}" ]]; then
    echo "missing ${UNIT_SRC}" >&2
    exit 1
fi

# systemd mounts these paths read-write; they must exist before the unit starts.
install -d -m 0755 /etc/sysspectogram /opt/sysspectogram /var/lib/sysspectogram /usr/lib/sysspectogram

install -Dm755 "${BIN}" /usr/lib/sysspectogram/sysspectogram-helper
install -Dm644 "${ROOT}/packaging/helper/sysspectogram-helper.service" /etc/systemd/system/sysspectogram-helper.service
install -Dm644 "${ROOT}/packaging/polkit/org.sysspectogram.helper.policy" /usr/share/polkit-1/actions/org.sysspectogram.helper.policy
install -Dm644 "${ROOT}/packaging/helper/sysusers.conf" /usr/lib/sysusers.d/sysspectogram.conf

systemd-sysusers /usr/lib/sysusers.d/sysspectogram.conf
systemctl daemon-reload
systemctl enable sysspectogram-helper.service
# restart, not enable --now: a running helper keeps the old binary and unit.
systemctl restart sysspectogram-helper.service

# Add the invoking user (not root) to the group that may use the socket.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    usermod -aG sysspectogram "${SUDO_USER}"
    if command -v setfacl >/dev/null 2>&1; then
        setfacl -m "u:${SUDO_USER}:rwx" /run/sysspectogram 2>/dev/null || true
        setfacl -m "u:${SUDO_USER}:rw" /run/sysspectogram/helper.sock 2>/dev/null || true
    fi
    echo "added ${SUDO_USER} to group sysspectogram — log out/in recommended; ACL applied for this boot"
    echo "  Start/Restart still needs polkit admin password (desktop agent)."
fi

systemctl --no-pager --full status sysspectogram-helper.service || true
echo "helper socket: /run/sysspectogram/helper.sock"
