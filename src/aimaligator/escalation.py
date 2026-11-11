"""Escalation: when the user says 'it wasn't me', hand the paths to an
antivirus scanner. AIMaligator never deletes or fixes anything - it launches
the scan and reports where it pointed the scanner.

Works alongside ANY antivirus:
- ``scan_command: "defender"``  -> Windows Defender's MpCmdRun (default)
- ``scan_command: "none"``      -> alert only, the user handles the scanner
- any other value               -> a custom command template containing
  ``{path}``, launched through the shell, e.g.
  ``"C:\\Program Files\\AV\\scanner.exe" /quick "{path}"``
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_CREATE_NO_WINDOW = 0x08000000


def _mpcmdrun_candidates() -> list[Path]:
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    return [
        Path(program_files) / "Windows Defender" / "MpCmdRun.exe",
        Path(program_files_x86) / "Windows Defender" / "MpCmdRun.exe",
    ]


def find_defender() -> Path | None:
    """Locate the Defender command-line scanner, if it exists."""
    for candidate in _mpcmdrun_candidates():
        if candidate.is_file():
            return candidate
    return None


def defender_template() -> str | None:
    exe = find_defender()
    if exe is None:
        return None
    return f'"{exe}" -Scan -ScanType 3 -File "{{path}}"'


def _defender_service_running() -> bool:
    """When a third-party antivirus is registered, Windows stops Defender.
    MpCmdRun then cannot scan - say so instead of pretending to launch."""
    try:
        result = subprocess.run(
            ["sc", "query", "WinDefend"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return "RUNNING" in result.stdout
    except OSError:
        return True  # cannot check - let the attempt happen anyway


def _run_template(template: str, path: str, use_shell: bool) -> int | None:
    """Run one scan command. Returns the pid, or None when it could not start."""
    try:
        if use_shell:
            proc = subprocess.Popen(
                template.replace("{path}", path),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW,
                shell=True,
            )
        else:
            proc = subprocess.Popen(
                [str(template), "-Scan", "-ScanType", "3", "-File", path],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_CREATE_NO_WINDOW,
            )
        return proc.pid
    except OSError as err:
        logger.warning("Could not start scan for %s: %s", path, err)
        return None


def launch_scan(cfg, paths: list[str]) -> list[tuple[str, str]]:
    """Start a scan of each path without blocking.

    Returns (path, status) pairs; status says what was launched (or why not).
    """
    template = cfg.scan_command
    use_shell = True

    if template == "none":
        return [
            (p, "no scanner configured (scan_command: none) - handle manually")
            for p in paths
        ]
    if template == "defender":
        resolved = defender_template()
        if resolved is None:
            return [
                (p, "Windows Defender scanner not found - handle manually")
                for p in paths
            ]
        if not _defender_service_running():
            return [
                (p, "Windows Defender is disabled (third-party antivirus "
                    "registered) - handle manually or set scan_command")
                for p in paths
            ]
        template, use_shell = resolved, False

    results: list[tuple[str, str]] = []
    for path in paths:
        pid = _run_template(template, path, use_shell)
        results.append((
            path,
            f"scan launched (pid {pid})" if pid is not None else "scan could not be started",
        ))
    return results