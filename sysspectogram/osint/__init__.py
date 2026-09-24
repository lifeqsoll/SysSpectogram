from __future__ import annotations

__all__ = ["ReconReport", "run_full_recon", "save_report"]


def __getattr__(name: str):
    if name in __all__:
        from sysspectogram.osint import recon as _recon

        return getattr(_recon, name)
    raise AttributeError(name)
