"""Process watching: check what children the LM Studio / Bionic processes
have, and flag any child whose program name is on the suspicious list."""

from __future__ import annotations

import logging
from pathlib import PurePath

from .alerts import Alert
from .config import Config

logger = logging.getLogger(__name__)


def _attr_value(obj: object, attr: str) -> str:
    """Read an attribute that may be a plain value (test fakes) or a method
    (real psutil.Process). Never raises - a vanished process reads as ''."""
    value = getattr(obj, attr, None)
    if callable(value):
        try:
            value = value()
        except Exception as err:  # psutil NoSuchProcess/AccessDenied
            logger.debug("Cannot read %s: %s", attr, err)
            return ""
    return value or ""


def is_suspicious(name: str, suspicious: frozenset[str]) -> bool:
    """True when *name* matches an entry on the suspicious program list."""
    stem = PurePath(name).stem.lower()
    return stem in suspicious


def is_allowed(name: str, allowed: frozenset[str]) -> bool:
    """True when *name* matches an entry on the allowed program list."""
    stem = PurePath(name).stem.lower()
    return stem in allowed


def child_alerts(cfg: Config, child_name: str) -> list[str]:
    """Reasons to alert on this child program, per the configured policy.

    ``suspicious-only``: alert when the program is on the suspicious list.
    ``allowlist``: alert on anything NOT on the allowed list (stricter -
    catches unknown launchers, at the cost of a few first-day prompts).
    """
    if cfg.child_policy == "allowlist":
        if not is_allowed(child_name, cfg.allowed_children):
            return ["not on the allowed-children list (allowlist policy)"]
        return []
    return ["on the suspicious-children list"] if is_suspicious(child_name, cfg.suspicious_children) else []


def children_of(procs: list, markers: tuple[str, ...]) -> list[tuple[object, str]]:
    """Collect (child, child_exe_name) for children of marker-matched parents.

    *procs* is any iterable of objects exposing ``pid``, ``name``, ``exe``,
    ``children()`` (psutil.Process duck type) so tests can pass fakes.
    """
    results: list[tuple[object, str]] = []
    parents: list[object] = []

    for proc in procs:
        exe = _attr_value(proc, "exe")
        name = _attr_value(proc, "name")
        haystack = f"{exe} {name}".lower()
        if any(marker in haystack for marker in markers):
            parents.append(proc)

    for parent in parents:
        try:
            kids = parent.children(recursive=True)
        except Exception as err:  # psutil raisesNoSuchProcess etc.
            logger.debug("Cannot list children of pid %s: %s", getattr(parent, "pid", "?"), err)
            continue
        for child in kids:
            exe = _attr_value(child, "exe")
            name = _attr_value(child, "name")
            results.append((child, PurePath(exe).name if exe else name))
    return results


def check(cfg: Config, procs: list | None = None) -> list[Alert]:
    """Scan (or re-scan *procs* if given, for tests) and flag suspicious children."""
    if procs is None:
        import psutil

        procs = list(psutil.process_iter(["pid", "name", "exe"]))

    alerts: list[Alert] = []
    for proc, child_name in children_of(procs, cfg.process_markers):
        for reason in child_alerts(cfg, child_name):
            exe = _attr_value(proc, "exe") or child_name
            alerts.append(Alert(
                "suspicious-child",
                exe,
                f"Spawned as a child of an AI app process "
                f"(pid {getattr(proc, 'pid', '?')}): {reason}",
            ))
    return alerts