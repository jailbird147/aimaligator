"""File integrity watching: hash every file under the watch roots and
compare against a stored baseline. Any change becomes an alert."""

from __future__ import annotations

import difflib
import datetime as _dt
import fnmatch
import hashlib
import json
import logging
import re
from pathlib import Path, PurePath

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
            lowered = str(candidate).lower()
            if any(fnmatch.fnmatch(lowered, g.lower()) for g in cfg.exclude_globs):
                continue
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

    For changed/removed text files the previous content (kept in the content
    store) is copied to ``state/changed-backups/<timestamp>/`` together with
    a unified diff, so the user can see exactly what changed before deciding
    whether it was theirs.
    """
    current = scan_roots(cfg)
    baseline = load_baseline(cfg)

    if baseline is None:
        save_baseline(cfg, current)
        _seed_content_store(cfg, current)
        return [Alert("info", str(_baseline_path(cfg)),
                      f"Baseline created with {len(current)} files")]

    index = _load_content_index(cfg)
    if index is None:
        # Content store introduced after this baseline was taken: seed it
        # silently from the current files so future changes can be diffed.
        _seed_content_store(cfg, current)
        index = _load_content_index(cfg) or {}

    new_paths: list[str] = []
    changed_paths: list[str] = []
    removed_paths: list[str] = []

    for path, digest in current.items():
        old = baseline.get(path)
        if old is None:
            new_paths.append(path)
        elif old != digest:
            changed_paths.append(path)
    for path in baseline:
        if path not in current:
            removed_paths.append(path)

    backup_note: dict[str, str] = {}
    backed = _load_backed(cfg)
    to_backup_changed = [p for p in changed_paths if backed.get(p) != current[p]]
    to_backup_removed = [p for p in removed_paths if backed.get(p) != "REMOVED"]
    if to_backup_changed or to_backup_removed:
        backup_note = _backup_changed(cfg, index, to_backup_changed,
                                      to_backup_removed, current)
        for p in to_backup_changed:
            backed[p] = current[p]
        for p in to_backup_removed:
            backed[p] = "REMOVED"
        _save_backed(cfg, backed)

    alerts: list[Alert] = []
    for path in new_paths:
        alerts.append(Alert("new-file", path, "File appeared under a watched root"))
    for path in changed_paths:
        detail = "File contents changed since baseline"
        if path in backup_note:
            detail += f" ({backup_note[path]})"
        alerts.append(Alert("changed-file", path, detail))
    for path in removed_paths:
        detail = "Watched file disappeared"
        if path in backup_note:
            detail += f" ({backup_note[path]})"
        alerts.append(Alert("removed-file", path, detail))

    return alerts


# --- content store & change backups -------------------------------------

CONTENT_DIR_NAME = "content-store"
BACKUP_DIR_NAME = "changed-backups"


def _content_dir(cfg: Config) -> Path:
    return cfg.state_dir / CONTENT_DIR_NAME


def _content_index_path(cfg: Config) -> Path:
    return _content_dir(cfg) / "index.json"


def _load_content_index(cfg: Config) -> dict[str, str] | None:
    """Map file path -> stored-copy filename. None means never seeded."""
    path = _content_index_path(cfg)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        logger.warning("Content store index unreadable, starting fresh: %s", err)
        return {}


def _save_content_index(cfg: Config, index: dict[str, str]) -> None:
    _content_dir(cfg).mkdir(parents=True, exist_ok=True)
    _content_index_path(cfg).write_text(
        json.dumps(index, indent=1), encoding="utf-8"
    )


def _store_name(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:20] + ".bin"


def _is_storable(digest: str) -> bool:
    """Big files (stat fingerprints) and key files have no stored content."""
    return not digest.startswith("stat:")


def _store_content(cfg: Config, index: dict[str, str], path: str,
                   digest: str) -> None:
    """Remember a small file's current content so later changes can be diffed."""
    if not _is_storable(digest):
        return
    try:
        data = Path(path).read_bytes()
    except OSError as err:
        logger.debug("Cannot store content of %s: %s", path, err)
        return
    name = _store_name(path)
    _content_dir(cfg).mkdir(parents=True, exist_ok=True)
    (_content_dir(cfg) / name).write_bytes(data)
    index[path] = name


def _seed_content_store(cfg: Config, current: dict[str, str]) -> None:
    index = _load_content_index(cfg) or {}
    for path, digest in current.items():
        if path not in index:
            _store_content(cfg, index, path, digest)
    _save_content_index(cfg, index)


BACKED_NAME = "backed-up-changes.json"


def _load_backed(cfg: Config) -> dict[str, str]:
    path = cfg.state_dir / BACKED_NAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_backed(cfg: Config, backed: dict[str, str]) -> None:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    (cfg.state_dir / BACKED_NAME).write_text(
        json.dumps(backed, indent=1), encoding="utf-8"
    )


def _sync_store(cfg: Config, index: dict[str, str],
                current: dict[str, str]) -> None:
    """Make the content store match the (just-accepted) baseline."""
    dirty = False
    for path, digest in current.items():
        if _is_storable(digest) and index.get(path) != _store_name(path):
            _store_content(cfg, index, path, digest)
            dirty = True
    for path in list(index):
        if path not in current:
            index.pop(path)
            dirty = True
    if dirty:
        _save_content_index(cfg, index)


def _make_diff(old: bytes, new: bytes) -> str | None:
    """Unified diff of two file versions; None when binary-looking."""
    if b"\x00" in old or b"\x00" in new:
        return None
    old_lines = old.decode("utf-8", errors="replace").splitlines()
    new_lines = new.decode("utf-8", errors="replace").splitlines()
    return "\n".join(difflib.unified_diff(old_lines, new_lines, lineterm=""))


def _backup_changed(cfg: Config, index: dict[str, str],
                    changed_paths: list[str], removed_paths: list[str],
                    current: dict[str, str]) -> dict[str, str]:
    """Save old versions + diffs of changed/removed files into a timestamped
    backup folder. Returns path -> human note for the alert detail."""
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = cfg.state_dir / BACKUP_DIR_NAME / stamp
    counter = 1
    while backup_dir.exists():
        backup_dir = cfg.state_dir / BACKUP_DIR_NAME / f"{stamp}-{counter}"
        counter += 1
    stamp = backup_dir.name
    notes: dict[str, str] = {}

    for path in changed_paths + removed_paths:
        stored_name = index.get(path)
        if stored_name is None:
            continue
        old_file = _content_dir(cfg) / stored_name
        try:
            old_data = old_file.read_bytes()
        except OSError:
            continue
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", PurePath(path).name)
            tag = "removed-" if path in removed_paths else "changed-"
            base = f"{tag}{hashlib.sha256(path.encode()).hexdigest()[:8]}-{safe}"
            (backup_dir / f"old-{base}").write_bytes(old_data)

            if path in removed_paths:
                notes[path] = f"old copy saved in state\\{BACKUP_DIR_NAME}\\{stamp}"
                continue
            try:
                new_data = Path(path).read_bytes()
            except OSError:
                continue
            (backup_dir / f"new-{base}").write_bytes(new_data)
            diff_text = _make_diff(old_data, new_data)
            if diff_text is None:
                notes[path] = f"binary change; copies in state\\{BACKUP_DIR_NAME}\\{stamp}"
                continue
            diff_text = f"--- {path} (old vs new)\n" + diff_text
            (backup_dir / f"{base}.diff").write_text(diff_text, encoding="utf-8")
            notes[path] = f"diff saved in state\\{BACKUP_DIR_NAME}\\{stamp}"
        except OSError as err:
            logger.warning("Could not back up %s: %s", path, err)
    return notes


def accept_current(cfg: Config) -> int:
    """Re-scan now and make that the new baseline ('it was me').

    Also syncs the content store to the accepted state and clears the
    'already backed up' record, so future changes are backed up again.
    Returns the number of files in the new baseline.
    """
    current = scan_roots(cfg)
    save_baseline(cfg, current)
    index = _load_content_index(cfg) or {}
    _sync_store(cfg, index, current)
    backed_file = cfg.state_dir / BACKED_NAME
    if backed_file.exists():
        backed_file.unlink()
    return len(current)