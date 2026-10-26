"""home update must use python -m pip (broken shebang-safe)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

from sysspectogram import friend_update as fu


def test_update_stack_invokes_python_dash_m_pip(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    venv_bin = home / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    py = venv_bin / "python"
    py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    py.chmod(0o755)
    # Deliberately NO venv/bin/pip — old code would FileNotFoundError.
    monkeypatch.setattr(fu, "_home", lambda: home)

    wheel = tmp_path / "pkg.whl"
    wheel.write_bytes(b"whl")
    agent = tmp_path / "sysspectogram-agent-x86_64-linux-musl"
    agent.write_bytes(b"agent")
    sums = f"{'a' * 64}  {wheel.name}\n".replace("a" * 64, __import__("hashlib").sha256(b"whl").hexdigest())

    assets = {
        wheel.name: "https://example.test/pkg.whl",
        "SHA256SUMS": "https://example.test/SHA256SUMS",
        "sysspectogram-agent-x86_64-linux-musl": "https://example.test/agent",
        "sysspectogram-agent-x86_64-linux-musl.sha256": "https://example.test/agent.sha256",
        "sysspectogram-agent-x86_64-linux-musl.minisig": "https://example.test/agent.minisig",
        f"{wheel.name}.minisig": "https://example.test/wheel.minisig",
    }
    urls = {
        assets[wheel.name]: b"whl",
        assets["SHA256SUMS"]: sums.encode(),
        assets["sysspectogram-agent-x86_64-linux-musl"]: b"agent",
        assets["sysspectogram-agent-x86_64-linux-musl.sha256"]: (
            __import__("hashlib").sha256(b"agent").hexdigest() + "  agent\n"
        ).encode(),
        assets["sysspectogram-agent-x86_64-linux-musl.minisig"]: b"sig-agent",
        assets[f"{wheel.name}.minisig"]: b"sig-wheel",
        "https://api.github.com/repos/lifeqsoll/SysSpectogram/releases/tags/v9.9.9": (
            __import__("json")
            .dumps(
                {
                    "assets": [
                        {"name": n, "browser_download_url": u} for n, u in assets.items()
                    ]
                }
            )
            .encode()
        ),
    }

    def fake_get(url: str) -> bytes:
        return urls[url]

    monkeypatch.setattr(fu, "_get", fake_get)
    monkeypatch.setattr(fu, "_verify_minisign", lambda *a, **k: None)
    # Treat target tag as newer than whatever is installed.
    monkeypatch.setattr(
        sys.modules["sysspectogram"],
        "__version__",
        "0.0.1",
        raising=False,
    )
    calls: list[list[str]] = []

    def fake_run(cmd, check=False, **kwargs):  # noqa: ANN001
        calls.append([str(c) for c in cmd])
        assert kwargs.get("capture_output") is True
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(fu.subprocess, "run", fake_run)
    out = fu.update_stack("v9.9.9")
    assert out.get("ok") is True, out
    pip_calls = [c for c in calls if "-m" in c and "pip" in c]
    assert pip_calls, calls
    assert pip_calls[0][:3] == [str(py), "-m", "pip"]
    assert not any(Path(c[0]).name == "pip" for c in calls if c)


def test_update_stack_refuses_unsigned(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    (home / ".venv" / "bin").mkdir(parents=True)
    monkeypatch.setattr(fu, "_home", lambda: home)
    wheel = "pkg.whl"
    assets = {
        wheel: "https://example.test/pkg.whl",
        "SHA256SUMS": "https://example.test/SHA256SUMS",
        "sysspectogram-agent-x86_64-linux-musl": "https://example.test/agent",
        "sysspectogram-agent-x86_64-linux-musl.sha256": "https://example.test/agent.sha256",
    }
    urls = {
        assets[wheel]: b"whl",
        assets["SHA256SUMS"]: (
            __import__("hashlib").sha256(b"whl").hexdigest() + f"  {wheel}\n"
        ).encode(),
        assets["sysspectogram-agent-x86_64-linux-musl"]: b"agent",
        assets["sysspectogram-agent-x86_64-linux-musl.sha256"]: (
            __import__("hashlib").sha256(b"agent").hexdigest() + "  agent\n"
        ).encode(),
        "https://api.github.com/repos/lifeqsoll/SysSpectogram/releases/tags/v9.9.9": (
            __import__("json")
            .dumps({"assets": [{"name": n, "browser_download_url": u} for n, u in assets.items()]})
            .encode()
        ),
    }
    monkeypatch.setattr(fu, "_get", lambda url: urls[url])
    out = fu.update_stack("v9.9.9")
    assert out.get("ok") is False
    assert "minisig" in str(out.get("error") or "").lower()


def test_embedded_pubkey_resolves():
    pub = fu._embedded_minisign_pub()
    assert pub is not None
    assert pub.is_file()
    assert "minisign" in pub.name


def test_update_stack_refuses_downgrade(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    (home / ".venv" / "bin").mkdir(parents=True)
    monkeypatch.setattr(fu, "_home", lambda: home)
    wheel = "pkg.whl"
    assets = {
        wheel: "https://example.test/pkg.whl",
        "SHA256SUMS": "https://example.test/SHA256SUMS",
        "sysspectogram-agent-x86_64-linux-musl": "https://example.test/agent",
        "sysspectogram-agent-x86_64-linux-musl.sha256": "https://example.test/agent.sha256",
        "sysspectogram-agent-x86_64-linux-musl.minisig": "https://example.test/agent.minisig",
        f"{wheel}.minisig": "https://example.test/wheel.minisig",
    }
    urls = {
        assets[wheel]: b"whl",
        assets["SHA256SUMS"]: (
            __import__("hashlib").sha256(b"whl").hexdigest() + f"  {wheel}\n"
        ).encode(),
        assets["sysspectogram-agent-x86_64-linux-musl"]: b"agent",
        assets["sysspectogram-agent-x86_64-linux-musl.sha256"]: (
            __import__("hashlib").sha256(b"agent").hexdigest() + "  agent\n"
        ).encode(),
        assets["sysspectogram-agent-x86_64-linux-musl.minisig"]: b"sig",
        assets[f"{wheel}.minisig"]: b"sig",
        "https://api.github.com/repos/lifeqsoll/SysSpectogram/releases/tags/v0.0.1": (
            __import__("json")
            .dumps({"assets": [{"name": n, "browser_download_url": u} for n, u in assets.items()]})
            .encode()
        ),
    }
    monkeypatch.setattr(fu, "_get", lambda url: urls[url])
    monkeypatch.setattr(fu, "_verify_minisign", lambda *a, **k: None)
    monkeypatch.setattr(
        sys.modules["sysspectogram"],
        "__version__",
        "9.9.9",
        raising=False,
    )
    out = fu.update_stack("v0.0.1")
    assert out.get("ok") is False
    assert "downgrade" in str(out.get("error") or "").lower()
