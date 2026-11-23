"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from aimaligator.config import Config


def make_config(
    watch_roots: list[Path],
    state_dir: Path,
    child_policy: str = "suspicious-only",
    allowed_children: set[str] | None = None,
    auto_scan: bool = False,
    scan_command: str = "defender",
    silent_notifications: bool = False,
) -> Config:
    return Config(
        watch_roots=tuple(watch_roots),
        process_markers=("lmstudio",),
        suspicious_children=frozenset({"certutil", "bitsadmin"}),
        max_hash_bytes=1024 * 1024,
        interval_seconds=300,
        state_dir=state_dir,
        child_policy=child_policy,
        allowed_children=frozenset(allowed_children or set()),
        auto_scan=auto_scan,
        scan_command=scan_command,
        silent_notifications=silent_notifications,
    )