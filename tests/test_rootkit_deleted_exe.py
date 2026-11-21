"""deleted_exe: package-upgrade downgrade vs tmpfs/memfd."""

from __future__ import annotations

import time
from pathlib import Path

from sysspectogram.audit.rootkit import (
    classify_deleted_exe,
    deleted_exe_replaced_by_upgrade,
    recent_package_upgrades,
)


def test_tmp_deleted_stays_high():
    f = classify_deleted_exe("/tmp/x (deleted)", pid=1, upgraded_packages={"systemd"})
    assert f["severity"] == "high"
    assert "suspicious" in f["note"]


def test_dev_shm_and_memfd_stay_high():
    assert classify_deleted_exe("/dev/shm/y (deleted)", upgraded_packages=set())["severity"] == "high"
    assert classify_deleted_exe("memfd:secret", upgraded_packages={"foo"})["severity"] == "high"


def test_no_package_owner_stays_high():
    f = classify_deleted_exe(
        "/usr/local/bin/weirdtool (deleted)",
        upgraded_packages={"systemd", "nginx"},
    )
    assert f["severity"] == "high"


def test_package_upgrade_downgrades_to_info():
    f = classify_deleted_exe(
        "/usr/lib/systemd/systemd-logind (deleted)",
        pid=None,
        upgraded_packages={"systemd"},
    )
    assert f["severity"] == "info"
    assert "package upgrade" in f["note"]
    assert deleted_exe_replaced_by_upgrade(
        "/usr/lib/systemd/systemd-logind (deleted)",
        upgraded_packages={"systemd"},
    )


def test_paranoid_disables_downgrade():
    f = classify_deleted_exe(
        "/usr/bin/nginx (deleted)",
        upgraded_packages={"nginx"},
        downgrade_on_upgrade=False,
    )
    assert f["severity"] == "high"


def test_parse_pacman_log(tmp_path: Path):
    log = tmp_path / "pacman.log"
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S+0000", time.localtime())
    log.write_text(
        f"[{stamp}] [ALPM] upgraded systemd (1-1 -> 2-1)\n"
        f"[{stamp}] [ALPM] installed nginx (1.0-1)\n",
        encoding="utf-8",
    )
    pkgs = recent_package_upgrades(
        now=time.time(),
        window_sec=86400,
        apt_history=None,
        dpkg_log=None,
        pacman_log=log,
    )
    assert "systemd" in pkgs
    assert "nginx" in pkgs


def test_parse_apt_history(tmp_path: Path):
    hist = tmp_path / "history.log"
    stamp = time.strftime("%Y-%m-%d  %H:%M:%S", time.localtime())
    hist.write_text(
        f"Start-Date: {stamp}\n"
        "Commandline: apt upgrade\n"
        "Upgrade: systemd:amd64 (1, 2), bash:amd64 (1, 2)\n"
        f"End-Date: {stamp}\n",
        encoding="utf-8",
    )
    pkgs = recent_package_upgrades(
        now=time.time(),
        window_sec=86400,
        apt_history=hist,
        dpkg_log=None,
        pacman_log=None,
    )
    assert "systemd" in pkgs
    assert "bash" in pkgs


def test_var_tmp_stays_high():
    assert (
        classify_deleted_exe("/var/tmp/payload (deleted)", upgraded_packages={"payload"})[
            "severity"
        ]
        == "high"
    )
