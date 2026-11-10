"""Network egress watching: alert the first time an AI app process is seen
connected to a remote address it has never contacted before.

Scope is deliberately narrow: only processes matching the configured
``process_markers`` (the AI apps themselves and the agent running inside
them). Every other program on the machine is someone else's job.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import json
import logging
from pathlib import Path

from .alerts import Alert
from .config import Config

logger = logging.getLogger(__name__)

STATE_NAME = "egress_seen.json"


@dataclasses.dataclass(frozen=True)
class EgressRecord:
    """One observed outbound connection."""

    pid: int
    display: str  # program name or path, human-readable
    endpoint: str  # "ip:port"


def _ignore_address(ip: str) -> bool:
    """Local/link-local/multicast addresses are infrastructure, not egress."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def _matches_markers(exe: str, name: str, markers: tuple[str, ...]) -> bool:
    haystack = f"{exe} {name}".lower()
    return any(marker in haystack for marker in markers)


def snapshot(procs=None) -> list[EgressRecord]:
    """Live outbound connections, deduplicated per (program, endpoint).

    ``procs`` may be a list of psutil.Process objects to restrict to (tests);
    otherwise every process is examined and filtered by markers later.
    """
    import psutil

    if procs is not None:
        iterable = [
            (p, getattr(p, "info", None) or {})
            for p in procs
        ]
        conns = []
        for p, _info in iterable:
            try:
                conns.extend(
                    (c, p) for c in p.net_connections(kind="inet")
                )
            except Exception as err:
                logger.debug("Cannot enumerate connections of %s: %s", p, err)
    else:
        conns = [(c, None) for c in psutil.net_connections(kind="inet")]

    records: dict[tuple[int, str, str], EgressRecord] = {}
    for conn, owner in conns:
        if conn.status not in ("ESTABLISHED", "SYN_SENT"):
            continue
        raddr = conn.raddr
        if not raddr or not raddr.ip:
            continue
        if _ignore_address(raddr.ip):
            continue

        pid = conn.pid
        display = ""
        if owner is not None:
            from .processes import _attr_value

            display = _attr_value(owner, "exe") or _attr_value(owner, "name")
        elif pid:
            try:
                proc = psutil.Process(pid)
                display = _exe_or_name(proc)
            except Exception:
                display = ""
        if not display:
            display = f"pid {pid}"

        records[(pid, display, f"{raddr.ip}:{raddr.port}")] = EgressRecord(
            pid=pid, display=display, endpoint=f"{raddr.ip}:{raddr.port}"
        )
    return list(records.values())


def _exe_or_name(proc) -> str:
    from .processes import _attr_value

    return _attr_value(proc, "exe") or _attr_value(proc, "name") or f"pid {proc.pid}"


def load_store(cfg: Config) -> dict[str, str]:
    path = cfg.state_dir / STATE_NAME
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        logger.warning("Egress store unreadable, starting fresh: %s", err)
        return {}


def save_store(cfg: Config, store: dict[str, str]) -> None:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    (cfg.state_dir / STATE_NAME).write_text(
        json.dumps(store, indent=1), encoding="utf-8"
    )


def check(cfg: Config, records: list[EgressRecord] | None = None) -> list[Alert]:
    """Alert on endpoints never seen before for a given program.

    The very first run (no store yet) creates the store silently - same
    philosophy as the file baseline: the current state is 'known good' until
    proven otherwise.
    """
    if records is None:
        records = snapshot()
        records = [
            r for r in records
            if _matches_markers(r.display, r.display, cfg.process_markers)
        ]

    store = load_store(cfg)
    first_run = not (cfg.state_dir / STATE_NAME).exists()

    alerts: list[Alert] = []
    now_key = _dt.datetime.now().isoformat(timespec="seconds")
    for rec in records:
        key = f"{rec.display}|{rec.endpoint}"
        if key in store:
            continue
        store[key] = now_key
        if not first_run:
            alerts.append(Alert(
                "new-egress",
                rec.display,
                f"first connection to {rec.endpoint}",
            ))

    save_store(cfg, store)
    return alerts