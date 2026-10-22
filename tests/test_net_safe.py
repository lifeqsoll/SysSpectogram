"""Pinned-IP / SSRF helpers."""

from __future__ import annotations

import pytest

from sysspectogram.net_safe import resolve_public_host


def test_literal_private_blocked():
    with pytest.raises(RuntimeError, match="private|blocked"):
        resolve_public_host("127.0.0.1")
    with pytest.raises(RuntimeError, match="private|blocked"):
        resolve_public_host("10.0.0.1")


def test_literal_private_allowed_opt_in():
    assert resolve_public_host("127.0.0.1", allow_private=True) == "127.0.0.1"


def test_localhost_name_blocked():
    with pytest.raises(RuntimeError):
        resolve_public_host("localhost")
