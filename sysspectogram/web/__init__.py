"""Local live dashboard + Telegram Mini App surface."""

from sysspectogram.web.bus import GLOBAL_BUS, LiveAlert, LiveBus
from sysspectogram.web.runtime import run_web_dashboard
from sysspectogram.web.server import start_web_server

__all__ = [
    "GLOBAL_BUS",
    "LiveAlert",
    "LiveBus",
    "run_web_dashboard",
    "start_web_server",
]
