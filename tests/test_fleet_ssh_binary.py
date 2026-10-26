"""ssh_binary() selects OpenSSH Client name (ssh / ssh.exe)."""

from __future__ import annotations

import shutil

from sysspectogram.fleet import ssh as fleet_ssh


def test_ssh_binary_prefers_ssh(monkeypatch):
    def which(name: str):
        if name == "ssh":
            return "/usr/bin/ssh"
        return None

    monkeypatch.setattr(shutil, "which", which)
    assert fleet_ssh.ssh_binary() == "/usr/bin/ssh"


def test_ssh_binary_falls_back_to_ssh_exe(monkeypatch):
    def which(name: str):
        if name == "ssh.exe":
            return r"C:\Windows\System32\OpenSSH\ssh.exe"
        return None

    monkeypatch.setattr(shutil, "which", which)
    assert fleet_ssh.ssh_binary().endswith("ssh.exe")


def test_ssh_binary_default_when_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert fleet_ssh.ssh_binary() == "ssh"
