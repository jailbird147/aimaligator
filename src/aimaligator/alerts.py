"""Alert records and delivery (log file + Windows toast)."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# CREATE_NO_WINDOW: keep the toast child from touching our console/stdio.
_CREATE_NO_WINDOW = 0x08000000

logger = logging.getLogger(__name__)

TOAST_SCRIPT_NAME = "toast.ps1"


@dataclass(frozen=True)
class Alert:
    """One thing worth telling the user about."""

    kind: str
    path: str
    detail: str
    when: _dt.datetime = field(default_factory=_dt.datetime.now)

    def as_line(self) -> str:
        """Single-line record for the alerts log."""
        return f"{self.when:%Y-%m-%d %H:%M:%S} | {self.kind} | {self.path} | {self.detail}"


def append_alerts(state_dir: Path, alerts: list[Alert]) -> Path:
    """Append alerts to the alerts log and return the log path."""
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / "alerts.log"
    with log_path.open("a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(alert.as_line() + "\n")
    return log_path


def send_toast(title: str, body: str) -> bool:
    """Show a Windows toast notification. Returns True on success."""
    script = Path(__file__).resolve().parents[2] / "scripts" / TOAST_SCRIPT_NAME
    if not script.is_file():
        logger.warning("Toast script missing: %s", script)
        return False
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script),
            ],
            env={**os.environ, "AIM_TOAST_TITLE": title, "AIM_TOAST_BODY": body},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=_CREATE_NO_WINDOW,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as err:
        logger.warning("Toast failed: %s", err)
        return False
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip() if result.stderr else ""
        logger.warning("Toast script failed: %s", stderr)
        return False
    return True