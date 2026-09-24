# Anomaly simulation scripts

[English](README.md) · [Русский](README_RU.md)

These scripts stress **this host only** (and localhost networking). Do not point them at other machines.

## Workflow

Terminal A — collect metrics:

```bash
python -m sysspectogram collect --out data/anomaly.csv --duration 1200
```

Terminal B — pick a generator:

```bash
python simulations/cpu_miner.py --duration 900
python simulations/net_flood_local.py --duration 900 --rate 100
python simulations/mem_pressure.py --duration 300 --mb 512
python simulations/disk_thrash.py --duration 300
```

Or:

```bash
chmod +x simulations/run_all.sh
./simulations/run_all.sh
```

Collect a separate `data/normal.csv` during normal use for Class 0.

Equivalent CLI entrypoints:

```bash
python -m sysspectogram simulate cpu|mem|disk|net ...
```

## Script flags

### `cpu_miner.py`

| Flag | Default | Description |
| --- | --- | --- |
| `--duration` | 900 | Seconds of CPU burn |
| `--workers` | auto (~half CPUs) | Worker processes |

### `mem_pressure.py`

| Flag | Default | Description |
| --- | --- | --- |
| `--duration` | 300 | Seconds |
| `--mb` | 512 | Megabytes to allocate and touch |

### `disk_thrash.py`

| Flag | Default | Description |
| --- | --- | --- |
| `--duration` | 300 | Seconds |
| `--block-mb` | 32 | Write/read block size |
| `--path` | `/tmp/sysspectogram_disk_thrash.bin` | Temporary file path |

### `net_flood_local.py`

| Flag | Default | Description |
| --- | --- | --- |
| `--duration` | 900 | Seconds |
| `--rate` | 80 | TCP connections per second to a local listener on `127.0.0.1` |

### `run_all.sh`

Environment overrides: `DURATION_CPU`, `DURATION_NET`, `DURATION_MEM`, `DURATION_DISK` (seconds).

## Safety

- CPU / memory / disk: local resource burn only  
- Network: bind and flood `127.0.0.1` only  
- No remote scanning tools  

## Intrusion lab (`simulations/intrusion/`)

Perimeter scenarios. No attacks on third-party hosts. External TEST-NET beacon requires `--lab`.

```bash
python simulations/intrusion/ssh_bruteforce_local.py --count 12 --out /tmp/fake_auth.log
python simulations/intrusion/port_scan_local.py --count 40
python simulations/intrusion/egress_beacon.py --local-sink --duration 8
python simulations/intrusion/lab_runner.py --lab egress_beacon
```

Run alongside `python -m sysspectogram watch-perimeter` or `guard`.
