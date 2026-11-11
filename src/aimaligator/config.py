"""Configuration loading for AIMaligator."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_NAME = "config.json"
DEFAULT_MAX_HASH_BYTES = 5242880
DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_SUSPICIOUS_CHILDREN = (
    "certutil", "bitsadmin", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "schtasks", "curl", "wget", "nc", "ncat",
)
DEFAULT_ALLOWED_CHILDREN = (
    "conhost", "cmd", "powershell", "pwsh", "openconsole",
    "node", "python", "pythonw", "ollama", "ollama_llama_server",
    "llama-server", "llamacpp", "lmlink-connector", "uninstallmonitor",
)


@dataclass(frozen=True)
class Config:
    """All watchdog settings, loaded once from a JSON file."""

    watch_roots: tuple[Path, ...]
    process_markers: tuple[str, ...]
    suspicious_children: frozenset[str]
    max_hash_bytes: int
    interval_seconds: int
    state_dir: Path
    child_policy: str = "suspicious-only"  # or "allowlist"
    allowed_children: frozenset[str] = frozenset()
    egress_watch: bool = True
    scan_command: str = "defender"  # "defender" | "none" | custom template
    exclude_globs: tuple[str, ...] = ()


def empty_config(config_path: Path) -> Config:
    """Sensible defaults for a machine where nothing has been detected yet."""
    return Config(
        watch_roots=(),
        process_markers=(),
        suspicious_children=frozenset(DEFAULT_SUSPICIOUS_CHILDREN),
        max_hash_bytes=DEFAULT_MAX_HASH_BYTES,
        interval_seconds=DEFAULT_INTERVAL_SECONDS,
        state_dir=config_path.parent / "state",
    )


def load_config(path: Path | None = None) -> Config:
    """Load config from *path*, or ``config.json`` beside the project root."""
    config_path = path or Path(__file__).resolve().parents[2] / DEFAULT_CONFIG_NAME
    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    raw = json.loads(config_path.read_text(encoding="utf-8"))

    # Optional keys keep older config files working.
    child_policy = raw.get("child_policy", "suspicious-only")
    if child_policy not in ("suspicious-only", "allowlist"):
        raise ValueError(f"child_policy must be 'suspicious-only' or 'allowlist', not {child_policy!r}")

    return Config(
        watch_roots=tuple(Path(p) for p in raw["watch_roots"]),
        process_markers=tuple(m.lower() for m in raw.get("process_markers", ())),
        suspicious_children=frozenset(
            n.lower().removesuffix(".exe") for n in raw.get("suspicious_children", ())
        ),
        max_hash_bytes=int(raw.get("max_hash_bytes", DEFAULT_MAX_HASH_BYTES)),
        interval_seconds=int(raw.get("interval_seconds", DEFAULT_INTERVAL_SECONDS)),
        state_dir=config_path.parent / raw["state_dir"],
        child_policy=child_policy,
        allowed_children=frozenset(
            n.lower().removesuffix(".exe") for n in raw.get("allowed_children", ())
        ),
        egress_watch=bool(raw.get("egress_watch", True)),
        scan_command=raw.get("scan_command", "defender"),
        exclude_globs=tuple(raw.get("exclude_globs", ())),
    )