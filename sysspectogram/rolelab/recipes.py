"""VPS Role Lab recipes for PC baseline packs (no VMs)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RoleRecipe:
    name: str
    description: str
    idle_frac: float = 0.55
    light_cpu_frac: float = 0.25
    net_burst_frac: float = 0.12
    anomaly_frac: float = 0.08
    cpu_workers: int = 1
    net_cps: int = 40
    mem_mb: int = 128
    prefer_http_server: bool = False
    prefer_nginx: bool = False
    prefer_docker_churn: bool = False


RECIPES: dict[str, RoleRecipe] = {
    "ssh": RoleRecipe(
        name="ssh",
        description="Quiet ssh-only VPS: mostly idle, rare net bursts",
        idle_frac=0.75,
        light_cpu_frac=0.12,
        net_burst_frac=0.08,
        anomaly_frac=0.05,
        cpu_workers=1,
        net_cps=20,
        mem_mb=64,
    ),
    "nginx": RoleRecipe(
        name="nginx",
        description="Web VPS: periodic HTTP-like CPU+net, short idle gaps",
        idle_frac=0.35,
        light_cpu_frac=0.35,
        net_burst_frac=0.22,
        anomaly_frac=0.08,
        cpu_workers=2,
        net_cps=80,
        mem_mb=256,
        prefer_http_server=True,
        prefer_nginx=True,
    ),
    "python": RoleRecipe(
        name="python",
        description="App VPS: sustained mid CPU + memory pressure waves",
        idle_frac=0.25,
        light_cpu_frac=0.45,
        net_burst_frac=0.15,
        anomaly_frac=0.15,
        cpu_workers=2,
        net_cps=40,
        mem_mb=512,
        prefer_http_server=True,
    ),
    "docker": RoleRecipe(
        name="docker",
        description="Docker host: bursty CPU/mem/net + short-lived process churn",
        idle_frac=0.30,
        light_cpu_frac=0.30,
        net_burst_frac=0.20,
        anomaly_frac=0.20,
        cpu_workers=2,
        net_cps=60,
        mem_mb=384,
        prefer_docker_churn=True,
    ),
    "wireguard": RoleRecipe(
        name="wireguard",
        description="VPN VPS: mostly idle with rare net bursts",
        idle_frac=0.70,
        light_cpu_frac=0.10,
        net_burst_frac=0.15,
        anomaly_frac=0.05,
        cpu_workers=1,
        net_cps=50,
        mem_mb=96,
    ),
    "panel": RoleRecipe(
        name="panel",
        description="Panel/3x-ui style: light HTTP + periodic admin bursts",
        idle_frac=0.40,
        light_cpu_frac=0.30,
        net_burst_frac=0.20,
        anomaly_frac=0.10,
        cpu_workers=2,
        net_cps=70,
        mem_mb=320,
        prefer_http_server=True,
    ),
}


def list_roles() -> list[str]:
    return sorted(RECIPES.keys())


def get_recipe(name: str) -> RoleRecipe:
    key = name.strip().lower()
    if key not in RECIPES:
        raise KeyError(f"unknown role {name!r}; choose from {list_roles()}")
    return RECIPES[key]
