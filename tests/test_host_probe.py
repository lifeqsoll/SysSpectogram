"""Tests for host_probe recommendations."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sysspectogram.host_probe import HostFacts, recommend


def test_recommend_lite_low_ram():
    facts = HostFacts(
        ram_gib=1.5,
        vcpus=1,
        container=False,
        has_onnx=True,
        has_torch=False,
        desktopish=False,
        systemd=True,
        reasons=["low RAM"],
    )
    rec = recommend(facts)
    assert rec.profile == "lite"
    assert rec.overlay["runtime"]["prefer"] == "notorch"
    assert rec.overlay["agent"]["mode"] == "userspace"
    assert rec.overlay["feedback"]["if_refit"] is False


def test_recommend_full_headroom():
    facts = HostFacts(
        ram_gib=8.0,
        vcpus=4,
        container=False,
        has_onnx=True,
        has_torch=True,
        desktopish=False,
        systemd=True,
        reasons=[],
    )
    rec = recommend(facts)
    assert rec.profile == "full"
    assert rec.overlay["flow"]["enabled"] is True


def test_container_forces_lite():
    facts = HostFacts(
        ram_gib=16.0,
        vcpus=8,
        container=True,
        has_onnx=False,
        has_torch=False,
        desktopish=False,
        systemd=False,
        reasons=["container"],
    )
    rec = recommend(facts)
    assert rec.profile == "lite"


@patch("sysspectogram.host_probe.collect_facts")
def test_recommend_calls_collect(mock_cf):
    mock_cf.return_value = HostFacts(
        ram_gib=2.0,
        vcpus=2,
        container=False,
        has_onnx=True,
        has_torch=False,
        desktopish=True,
        systemd=True,
        reasons=[],
    )
    rec = recommend()
    assert any(i.key == "agent.mode" for i in rec.items)
