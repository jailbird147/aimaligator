"""File integrity watching: hash every file under the watch roots and
compare against a stored baseline. Any change becomes an alert."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from .alerts import Alert
from .config import Config

logger = logging.getLogger(__name__)

BASELINE_NAME = "baseline.json"


def sha256_of(path: Path) -> str | None:
    """Return the SHA-256 hex digest of *path*, or None if unreadable."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as err:
        logger.debug("Cannot hash %s: %s", path, err)
        return None


_KEY_FILE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed448",
    "authorized_keys", "known_hosts",
}
_KEY_FILE_SUFFIXES = {".key", ".pem", ".ppk", ".pfx", ".p12", ".pub"}
_KEY_FILE_PREFIXES = ("id_",)


def is_key_file(path: Path) -> bool:
    """True for SSH/crypto keys and similar sensitive files.

    Covers public keys too: some security software kills processes that OPEN
    files named like SSH keys (even ``id_ed25519.pub``), and the watchdog has
    no business reading key material anyway. Such files are fingerprinted by
    size+mtime only (stat never opens the file), which still detects
    tampering.
    """
    name = path.name.lower()
    return (
        name in _KEY_FILE_NAMES
        or name.startswith(_KEY_FILE_PREFIXES)
        or path.suffix.lower() in _KEY_FILE_SUFFIXES
    )


def fingerprint_of(path: Path, max_bytes: int) -> str | None:
    """Fingerprint *path*: content hash for small ordinary files, size+mtime
    for big ones (model weights) and for key files (which must not be read)."""
    try:
        stat = path.stat()
    except OSError as err:
        logger.debug("Cannot stat %s: %s", path, err)
        return None
    if stat.st_size <= max_bytes and not is_key_file(path):
        return sha256_of(path)
    return f"stat:{stat.st_size}:{stat.st_mtime_ns}"


def scan_roots(cfg: Config) -> dict[str, str]:
    """Map ``relative path -> sha256`` for every readable file under the roots."""
    hashes: dict[str, str] = {}
    for root in cfg.watch_roots:
        if root.is_file():
            digest = fingerprint_of(root, cfg.max_hash_bytes)
            if digest is not None:
                hashes[str(root)] = digest
            continue
        if not root.is_dir():
            logger.warning("Watch root missing: %s", root)
            continue
        for candidate in root.rglob("*"):
            if not candidate.is_file():
                continue
            if cfg.state_dir in candidate.parents:
                continue  # never track our own baseline/alert files
            digest = fingerprint_of(candidate, cfg.max_hash_bytes)
            if digest is not None:
                hashes[str(candidate)] = digest
    return hashes


def _baseline_path(cfg: Config) -> Path:
    return cfg.state_dir / BASELINE_NAME


def load_baseline(cfg: Config) -> dict[str, str] | None:
    path = _baseline_path(cfg)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_baseline(cfg: Config, hashes: dict[str, str]) -> Path:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(cfg)
    path.write_text(json.dumps(hashes, indent=1), encoding="utf-8")
    return path


def check(cfg: Config) -> list[Alert]:
    """Compare current fingerprints to the baseline.

    On the first run there is no baseline: one is created and an info note is
    returned. Afterwards the baseline is NEVER updated automatically - the
    user confirms changes (accept_current) or escalates. This means tampering
    keeps alerting on every check instead of being silently absorbed.
    """
    current = scan_roots(cfg)
    baseline = load_baseline(cfg)

    if baseline is None:
        save_baseline(cfg, current)
        return [Alert("info", str(_baseline_path(cfg)),
                      f"Baseline created with {len(current)} files")]

    alerts: list[Alert] = []

    for path, digest in current.items():
        old = baseline.get(path)
        if old is None:
            alerts.append(Alert("new-file", path, "File appeared under a watched root"))
        elif old != digest:
            alerts.append(Alert("changed-file", path, "File contents changed since baseline"))

    for path in baseline:
        if path not in current:
            alerts.append(Alert("removed-file", path, "Watched file disappeared"))

    return alerts


def accept_current(cfg: Config) -> int:
    """Re-scan now and make that the new baseline ('it was me').

    Returns the number of files in the new baseline.
    """
    current = scan_roots(cfg)
    save_baseline(cfg, current)
    return len(current)