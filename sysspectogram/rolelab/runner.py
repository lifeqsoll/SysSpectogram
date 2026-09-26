"""Run role recipes while collecting metrics CSV (synthetic / hybrid)."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from sysspectogram.collect.daemon import CollectDaemon
from sysspectogram.collect.metrics import MetricsCollector
from sysspectogram.rolelab.recipes import RoleRecipe, get_recipe
from sysspectogram.simulate.loads import burn_cpu, flood_local_net, pressure_memory


def _http_handler_factory():
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):  # noqa: A003
            return

    return _H


def _start_local_http() -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _http_handler_factory())
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, t


def _curl_loop(port: int, stop: threading.Event, rps: float = 8.0) -> None:
    interval = 1.0 / max(rps, 0.1)
    while not stop.is_set():
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3) as c:
                c.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                c.recv(4096)
        except OSError:
            pass
        stop.wait(interval)


def _proc_churn(stop: threading.Event, period: float = 0.4) -> None:
    """Mimic docker-ish short-lived processes without docker."""
    while not stop.is_set():
        try:
            subprocess.run(
                ["bash", "-c", "true"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["sleep", "0.05"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass
        stop.wait(period)


def _try_nginx_reload() -> bool:
    if not shutil.which("nginx"):
        return False
    r = subprocess.run(
        ["nginx", "-t"],
        capture_output=True,
        text=True,
        check=False,
    )
    return r.returncode == 0


def _try_docker_hello(stop: threading.Event) -> bool:
    if not shutil.which("docker"):
        return False
    # One lightweight pull/run if daemon reachable; ignore failures
    def job() -> None:
        while not stop.is_set():
            subprocess.run(
                ["docker", "run", "--rm", "hello-world"],
                capture_output=True,
                check=False,
                timeout=60,
            )
            stop.wait(45.0)

    threading.Thread(target=job, daemon=True).start()
    return True


def _phase_seconds(total: float, frac: float) -> float:
    return max(1.0, total * max(0.0, frac))


def run_workload(recipe: RoleRecipe, duration_sec: float, *, hybrid: bool = True) -> dict[str, Any]:
    """Drive synthetic (and optional hybrid) load for `duration_sec`. Blocking."""
    notes: list[str] = []
    stop = threading.Event()
    http_srv = None
    http_port = None
    end = time.monotonic() + duration_sec

    if hybrid and (recipe.prefer_http_server or recipe.prefer_nginx):
        if recipe.prefer_nginx and _try_nginx_reload():
            notes.append("nginx present (configtest ok); using local http.server for traffic")
        http_srv, http_port, _ = _start_local_http()
        notes.append(f"local http.server 127.0.0.1:{http_port}")
        threading.Thread(
            target=_curl_loop, args=(http_port, stop, float(max(4, recipe.net_cps // 10))), daemon=True
        ).start()

    docker_used = False
    if hybrid and recipe.prefer_docker_churn:
        docker_used = _try_docker_hello(stop)
        if docker_used:
            notes.append("docker hello-world churn enabled")
        else:
            notes.append("docker unavailable - synthetic proc churn")
            threading.Thread(target=_proc_churn, args=(stop,), daemon=True).start()
    elif recipe.prefer_docker_churn:
        threading.Thread(target=_proc_churn, args=(stop,), daemon=True).start()
        notes.append("synthetic proc churn")

    # Schedule repeating cycle of idle / cpu / net / anomaly until duration ends
    cycle = [
        ("idle", recipe.idle_frac, None),
        ("cpu", recipe.light_cpu_frac, "cpu"),
        ("net", recipe.net_burst_frac, "net"),
        ("anomaly", recipe.anomaly_frac, "anomaly"),
    ]
    # Normalize fracs
    s = sum(c[1] for c in cycle) or 1.0
    cycle = [(n, f / s, k) for n, f, k in cycle]

    try:
        while time.monotonic() < end:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            # one full cycle scaled to min(60s, remaining) chunks
            chunk = min(60.0, remaining)
            for name, frac, kind in cycle:
                if time.monotonic() >= end:
                    break
                sec = min(_phase_seconds(chunk, frac), end - time.monotonic())
                if sec <= 0:
                    break
                if kind is None:
                    time.sleep(sec)
                elif kind == "cpu":
                    burn_cpu(sec, workers=recipe.cpu_workers)
                elif kind == "net":
                    if http_port is None:
                        flood_local_net(sec, connections_per_sec=recipe.net_cps)
                    else:
                        # curl_loop already running; add short flood for burstiness
                        flood_local_net(min(sec, 5.0), connections_per_sec=recipe.net_cps)
                        time.sleep(max(0.0, sec - 5.0))
                elif kind == "anomaly":
                    # labeled stress for anomaly windows
                    half = sec / 2.0
                    burn_cpu(half, workers=max(2, recipe.cpu_workers + 1))
                    pressure_memory(half, megabytes=min(1024, recipe.mem_mb * 2))
    finally:
        stop.set()
        if http_srv is not None:
            http_srv.shutdown()

    return {
        "role": recipe.name,
        "duration_sec": duration_sec,
        "hybrid": hybrid,
        "docker_used": docker_used,
        "notes": notes,
    }


def run_role_collect(
    role: str,
    *,
    out_dir: Path,
    duration_sec: float = 600.0,
    hybrid: bool = True,
    interval_sec: float = 1.0,
) -> dict[str, Any]:
    """Collect CSV while running recipe workload in a background thread."""
    recipe = get_recipe(role)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "normal.csv"
    collector = MetricsCollector(max_cores=16, socket_sample_every=5)
    daemon = CollectDaemon(collector, interval_sec=interval_sec, csv_path=csv_path)

    load_meta: dict[str, Any] = {}
    err: list[BaseException] = []

    def load_job() -> None:
        try:
            load_meta.update(run_workload(recipe, duration_sec, hybrid=hybrid))
        except BaseException as exc:  # noqa: BLE001
            err.append(exc)

    t = threading.Thread(target=load_job, name=f"rolelab-{role}", daemon=True)
    t.start()
    n = daemon.run(duration_sec=duration_sec)
    t.join(timeout=30.0)
    if err:
        raise RuntimeError(f"workload failed: {err[0]}") from err[0]

    anom_dur = min(180.0, max(75.0, duration_sec * 0.1))
    anom_path = out_dir / "anomaly.csv"
    daemon_a = CollectDaemon(
        MetricsCollector(max_cores=16, socket_sample_every=5),
        interval_sec=interval_sec,
        csv_path=anom_path,
    )

    def anom_job() -> None:
        burn_cpu(anom_dur * 0.5, workers=max(2, recipe.cpu_workers + 1))
        pressure_memory(anom_dur * 0.3, megabytes=min(1536, recipe.mem_mb * 3))
        flood_local_net(anom_dur * 0.2, connections_per_sec=recipe.net_cps * 2)

    ta = threading.Thread(target=anom_job, daemon=True)
    ta.start()
    n_anom = daemon_a.run(duration_sec=anom_dur)
    ta.join(timeout=30.0)

    manifest = {
        "schema": "sysspectogram.rolelab.v1",
        "role": recipe.name,
        "description": recipe.description,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "mode": "hybrid" if hybrid else "synthetic",
        "duration_sec": duration_sec,
        "samples_normal": n,
        "samples_anomaly": n_anom,
        "normal_csv": str(csv_path.name),
        "anomaly_csv": str(anom_path.name),
        "workload": load_meta,
    }
    man_path = out_dir / "manifest.json"
    man_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _csv_row_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        n = sum(1 for _ in fh)
    return max(0, n - 1)


def _min_rows_for_window(window_size: int = 60) -> int:
    return max(window_size + 15, 75)


def ensure_role_csvs(role_dir: Path, *, min_rows: int | None = None) -> tuple[Path, Path]:
    """Recover train inputs after interrupted collect."""
    role_dir = Path(role_dir)
    need = int(min_rows if min_rows is not None else _min_rows_for_window())
    man_path = role_dir / "manifest.json"
    if man_path.exists():
        man = json.loads(man_path.read_text(encoding="utf-8"))
        normal = role_dir / man.get("normal_csv", "normal.csv")
        anomaly = role_dir / man.get("anomaly_csv", "anomaly.csv")
    else:
        normal = role_dir / "normal.csv"
        anomaly = role_dir / "anomaly.csv"
        man = {
            "schema": "sysspectogram.rolelab.v1",
            "role": role_dir.name,
            "normal_csv": "normal.csv",
            "anomaly_csv": "anomaly.csv",
            "note": "recovered from incomplete run",
        }
    if not normal.exists() or _csv_row_count(normal) < 10:
        raise FileNotFoundError(f"missing/short {normal} - re-run role-lab run")

    def _synth_anomaly(dur: float) -> int:
        daemon_a = CollectDaemon(
            MetricsCollector(max_cores=16, socket_sample_every=5),
            interval_sec=1.0,
            csv_path=anomaly,
        )

        def anom_job() -> None:
            burn_cpu(dur * 0.5, workers=3)
            pressure_memory(dur * 0.3, megabytes=512)
            flood_local_net(dur * 0.2, connections_per_sec=100)

        t = threading.Thread(target=anom_job, daemon=True)
        t.start()
        n = daemon_a.run(duration_sec=dur)
        t.join(timeout=max(30.0, dur + 5.0))
        return int(n)

    if not anomaly.exists() or _csv_row_count(anomaly) < need:
        n_anom = _synth_anomaly(float(need + 5))
        man["anomaly_csv"] = anomaly.name
        man["samples_anomaly"] = n_anom
        man["note"] = man.get("note") or "anomaly recovered/extended for train"
        man_path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    elif not man_path.exists():
        man_path.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    return normal, anomaly


def train_role_pack(
    role_dir: Path,
    *,
    out_artifacts: Path,
    pack_out: Path | None = None,
    epochs: int = 12,
) -> dict[str, Any]:
    """build-dataset, train, optional pack from a role-lab directory."""
    from sysspectogram.preprocess.dataset_builder import build_dataset
    from sysspectogram.ml.train import train_models
    from sysspectogram.profiles import pack_profile

    role_dir = Path(role_dir)
    normal, anomaly = ensure_role_csvs(role_dir, min_rows=_min_rows_for_window(60))
    man = {}
    man_path = role_dir / "manifest.json"
    if man_path.exists():
        man = json.loads(man_path.read_text(encoding="utf-8"))
    role = man.get("role") or role_dir.name
    n_norm = _csv_row_count(normal)
    n_anom = _csv_row_count(anomaly)
    window_size = min(60, max(16, min(n_norm, n_anom) - 10))
    stride = 5 if window_size >= 40 else max(2, window_size // 8)
    ds_dir = role_dir / "dataset"
    meta = build_dataset(
        normal_csvs=[normal],
        anomaly_csvs=[anomaly],
        out_dir=ds_dir,
        window_size=window_size,
        stride=stride,
        write_png=False,
        val_ratio=0.2,
        seed=42,
        balance=True,
        max_normal_cpu_mean=None,
        min_anomaly_cpu_mean=None,
        max_normal_mem_mean=None,
        min_anomaly_mem_mean=None,
        max_normal_pkt_mean=None,
        min_anomaly_pkt_mean=None,
        min_anomaly_cpu_std_max=None,
    )
    out_artifacts = Path(out_artifacts)
    train_models(
        dataset_dir=ds_dir,
        out_dir=out_artifacts,
        epochs=epochs,
        batch_size=32,
        lr=0.001,
        cnn_weight=0.55,
        iforest_weight=0.45,
        recall_target=0.85,
        seed=42,
    )
    result: dict[str, Any] = {"dataset": meta, "artifacts": str(out_artifacts), "role": role}
    try:
        from sysspectogram.ml.export_onnx import export_cnn_onnx

        info = export_cnn_onnx(out_artifacts)
        result["onnx"] = info.get("path") or str(out_artifacts / "cnn.onnx")
    except Exception as exc:  # noqa: BLE001
        result["onnx_skip"] = str(exc)

    if pack_out is not None:
        info = pack_profile(
            name=f"profile-{role}-v1",
            role=role,
            host_artifacts=out_artifacts,
            out_tar=Path(pack_out),
            description=f"Role-lab baseline for {role} (PC synthetic/hybrid).",
        )
        result["pack"] = info
        try:
            import hashlib

            tar = Path(pack_out)
            digest = hashlib.sha256(tar.read_bytes()).hexdigest()
            sid = tar.with_name(tar.name + ".sha256")
            sid.write_text(f"{digest}  {tar.name}\n", encoding="utf-8")
            result["pack_sha256"] = digest
            result["pack_sha256_path"] = str(sid)
        except OSError:
            pass
    return result
