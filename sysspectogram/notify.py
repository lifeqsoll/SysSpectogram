from __future__ import annotations

import shutil
import subprocess
from typing import Iterable


def notify(title: str, body: str) -> None:
    if shutil.which("notify-send") is None:
        return
    try:
        subprocess.run(
            ["notify-send", "--app-name=SysSpectogram", title, body],
            check=False,
            timeout=5,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError):
        return


def format_process_lines(rows: Iterable[dict]) -> str:
    lines = []
    for row in rows:
        lines.append(
            f"pid={row.get('pid')} name={row.get('name')} "
            f"cpu={row.get('cpu_percent')}% mem={row.get('memory_percent')}%"
        )
    return "\n".join(lines)
