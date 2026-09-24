from __future__ import annotations

import multiprocessing as mp
import socket
import threading
import time
from pathlib import Path


def _cpu_worker(stop_at: float) -> None:
    while time.time() < stop_at:
        x = 0
        for i in range(100_000):
            x += i * i


def burn_cpu(duration_sec: float, workers: int | None = None) -> None:
    workers = workers or max(1, (mp.cpu_count() or 2) // 2)
    stop_at = time.time() + duration_sec
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_cpu_worker, args=(stop_at,)) for _ in range(workers)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()


def pressure_memory(duration_sec: float, megabytes: int = 512) -> None:
    blocks: list[bytearray] = []
    try:
        chunk = 16 * 1024 * 1024
        target = megabytes * 1024 * 1024
        allocated = 0
        while allocated < target:
            blocks.append(bytearray(chunk))
            allocated += chunk
        end = time.time() + duration_sec
        while time.time() < end:
            for b in blocks:
                b[0] = (b[0] + 1) % 256
            time.sleep(0.05)
    finally:
        blocks.clear()


def thrash_disk(duration_sec: float, path: Path | None = None, block_mb: int = 32) -> None:
    path = path or Path("/tmp/sysspectogram_disk_thrash.bin")
    end = time.time() + duration_sec
    data = b"\0" * (block_mb * 1024 * 1024)
    try:
        while time.time() < end:
            with path.open("wb") as fh:
                fh.write(data)
                fh.flush()
            with path.open("rb") as fh:
                _ = fh.read()
    finally:
        if path.exists():
            path.unlink(missing_ok=True)


def _serve(sock: socket.socket, stop_flag: threading.Event) -> None:
    sock.settimeout(0.5)
    while not stop_flag.is_set():
        try:
            conn, _ = sock.accept()
            with conn:
                try:
                    conn.recv(4096)
                except OSError:
                    pass
        except socket.timeout:
            continue
        except OSError:
            break


def flood_local_net(duration_sec: float, connections_per_sec: int = 80) -> None:
    stop_flag = threading.Event()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(128)
    t = threading.Thread(target=_serve, args=(srv, stop_flag), daemon=True)
    t.start()
    end = time.time() + duration_sec
    try:
        while time.time() < end:
            batch_start = time.time()
            for _ in range(connections_per_sec):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2) as c:
                        c.sendall(b"GET / HTTP/1.0\r\n\r\n")
                except OSError:
                    pass
            elapsed = time.time() - batch_start
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
    finally:
        stop_flag.set()
        srv.close()
        t.join(timeout=2)


def burn_gpu(duration_sec: float, size: int = 2048) -> None:
    """Light GPU load via torch CUDA matmul. Soft-fail if no CUDA."""
    try:
        import torch
    except ImportError:
        print("torch not installed; GPU sim skipped")
        return
    if not torch.cuda.is_available():
        print("CUDA not available; GPU sim skipped")
        return
    device = torch.device("cuda")
    a = torch.randn(size, size, device=device)
    b = torch.randn(size, size, device=device)
    end = time.time() + duration_sec
    while time.time() < end:
        c = a @ b
        a = c
        torch.cuda.synchronize()
