"""Role lab unit tests (short synthetic run)."""

from __future__ import annotations

from pathlib import Path

from sysspectogram.rolelab import get_recipe, list_roles, run_role_collect


def test_list_roles():
    roles = list_roles()
    assert "ssh" in roles and "nginx" in roles
    assert "wireguard" in roles and "panel" in roles


def test_get_recipe():
    r = get_recipe("nginx")
    assert r.prefer_http_server


def test_run_role_collect_short(tmp_path: Path):
    man = run_role_collect(
        "ssh",
        out_dir=tmp_path / "ssh",
        duration_sec=8.0,
        hybrid=False,
    )
    assert man["samples_normal"] >= 5
    assert (tmp_path / "ssh" / "normal.csv").exists()
    assert (tmp_path / "ssh" / "anomaly.csv").exists()
    assert (tmp_path / "ssh" / "manifest.json").exists()


def test_ensure_recovers_short_anomaly(tmp_path: Path):
    from sysspectogram.rolelab import ensure_role_csvs
    from sysspectogram.rolelab.runner import _csv_row_count

    d = tmp_path / "nginx"
    d.mkdir()
    # minimal normal with header + rows
    cols = "timestamp,cpu_percent,mem_percent,net_packets_sent_per_s\n"
    rows = "".join(f"2020-01-01T00:00:{i:02d}Z,{i%10},{20+i%5},{i}\n" for i in range(80))
    (d / "normal.csv").write_text(cols + rows, encoding="utf-8")
    (d / "anomaly.csv").write_text(cols + "2020-01-01T00:01:00Z,1,1,1\n", encoding="utf-8")
    n, a = ensure_role_csvs(d, min_rows=20)
    assert _csv_row_count(a) >= 20
    assert n.exists()
