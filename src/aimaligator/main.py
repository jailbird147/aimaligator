"""Command-line entry point and the watch loop."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import alerts as alerts_mod
from . import detect, escalation, fingerprints, network, processes
from .alerts import Alert
from .config import Config, DEFAULT_CONFIG_NAME, empty_config, load_config

logger = logging.getLogger("aimaligator")


def run_once(cfg: Config) -> list[Alert]:
    """One full pass: file fingerprints, child-process check, egress check."""
    found: list[Alert] = []
    found.extend(fingerprints.check(cfg))
    found.extend(processes.check(cfg))
    if cfg.egress_watch:
        try:
            found.extend(network.check(cfg))
        except Exception as err:  # never let one watcher kill the others
            logger.warning("Egress watch failed this cycle: %s", err)
    return found


def handle(cfg: Config, found: list[Alert]) -> None:
    """Log every alert, write them to the alerts log, and toast the user."""
    for alert in found:
        logger.warning("%s | %s", alert.kind, alert.path)

    if not found:
        return

    log_path = alerts_mod.append_alerts(cfg.state_dir, found)
    title = f"AIMaligator: {len(found)} alert(s)"
    body = "; ".join(f"{a.kind}: {a.path}" for a in found[:3])
    if len(found) > 3:
        body += f" ... see {log_path}"
    alerts_mod.send_toast(title, body)
    print(f"ALERTS written to {log_path}")
    for alert in found:
        print(alert.as_line())


def _is_interactive() -> bool:
    """True when a human can actually answer a question right now."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (OSError, ValueError):
        return False


def resolve_with_user(cfg: Config, found: list[Alert], config_path: Path | None = None) -> None:
    """Ask 'was this you?' when a human is present.

    yes -> the current file state becomes the new baseline (automatic
    rebaseline). no -> hand the paths to Windows Defender and keep the old
    baseline, so the tampering keeps alerting on later checks.
    """
    real = [a for a in found if a.kind != "info"]
    if not real or not _is_interactive():
        return

    try:
        answer = input(
            f"Was this you ({len(real)} alert(s))? "
            "[y]es = update baseline / [n]o = scan with Defender: "
        )
    except (EOFError, KeyboardInterrupt, OSError):
        return
    answer = answer.strip().lower()

    if answer.startswith("y"):
        # Re-read the config before accepting: a prompt can sit open across a
        # config change, and accepting with a stale config would silently
        # unwatch roots added since this process started.
        try:
            cfg = load_config(config_path)
        except (OSError, KeyError, ValueError) as err:
            logger.warning("Config reload before accept failed, keeping previous: %s", err)
        count = fingerprints.accept_current(cfg)
        logger.info("Baseline updated: %s files marked as known-good", count)
        print(f"Baseline updated ({count} files).", flush=True)
        return

    # 'no' (or anything else): escalate, do NOT touch the baseline.
    scannable = [a.path for a in real if Path(a.path).exists()]
    results = escalation.launch_scan(cfg, scannable)
    notes = [
        Alert("escalated", path, status)
        for path, status in results
    ]
    alerts_mod.append_alerts(cfg.state_dir, notes)
    started = sum(1 for _, status in results if "pid" in status)
    alerts_mod.send_toast(
        "AIMaligator: escalated to antivirus",
        f"Scan started for {started} of {len(results)} path(s). "
        "Baseline NOT updated - alerts will repeat.",
    )
    for note in notes:
        print(note.as_line(), flush=True)


def _default_config_path() -> Path:
    """Config lives in the working directory; fall back to the dev layout.

    For an installed package (wheel), ``Path(__file__).parents[2]`` would
    point into site-packages, so the working directory wins when it has a
    config. Fresh installs create one in the working directory.
    """
    cwd_candidate = Path.cwd() / DEFAULT_CONFIG_NAME
    if cwd_candidate.is_file():
        return cwd_candidate
    legacy = Path(__file__).resolve().parents[2] / DEFAULT_CONFIG_NAME
    if legacy.is_file():
        return legacy
    return cwd_candidate


def run_init(config_path: Path | None, assume_yes: bool) -> int:
    """Detect installed AI apps, add them to the config, take a baseline."""
    path = config_path or _default_config_path()
    try:
        current = load_config(path)
    except FileNotFoundError:
        current = empty_config(path)
        print(f"No config found - starting fresh: {path}")

    found = detect.detect_all()

    # Self-watch: the watchdog must be watched too. Add this install's own
    # code, scripts and config so tampering with AIMaligator itself alerts.
    self_roots = [
        path.parent / "src",
        path.parent / "scripts",
        path.parent / "skill",
        path.parent / "install.ps1",
        path.parent / "config.json",
    ]
    found.append(detect.Detected(
        "AIMaligator (self-watch)",
        roots=[r for r in self_roots if r.exists()],
        markers=[],
    ))

    if not found:
        print("No known AI apps detected - config unchanged.")
        return 0

    have = {str(r).casefold() for r in current.watch_roots}
    added_roots: list[Path] = []
    added_markers: set[str] = set()
    for app in found:
        print(f"Found: {app.name}")
        for root in app.existing_roots():
            status = "already watched" if str(root).casefold() in have else "NEW"
            print(f"  watch: {root} [{status}]")
            if status == "NEW":
                added_roots.append(root)
                have.add(str(root).casefold())
        for marker in app.markers:
            if marker.casefold() not in {m.casefold() for m in current.process_markers}:
                added_markers.add(marker)

    if not added_roots and not added_markers:
        print("Nothing new to add - config unchanged.")
        return 0

    if not assume_yes and _is_interactive():
        answer = input("Add these to the config and take a new baseline? [y/N]: ")
        if not answer.strip().lower().startswith("y"):
            print("Cancelled - config unchanged.")
            return 0

    all_roots = list(current.watch_roots) + added_roots
    all_markers = list(current.process_markers) + sorted(added_markers)
    raw = {
        "watch_roots": [str(r) for r in all_roots],
        "process_markers": all_markers,
        "suspicious_children": sorted(current.suspicious_children),
        "max_hash_bytes": current.max_hash_bytes,
        "interval_seconds": current.interval_seconds,
        "state_dir": str(current.state_dir),
    }
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    print(f"Config updated: {path}")

    fresh = load_config(path)
    count = fingerprints.accept_current(fresh)
    print(f"Baseline taken: {count} files marked as known-good.")
    return 0


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aimaligator",
        description="Alert-only watchdog for Bionic / LM Studio.",
    )
    parser.add_argument("--config", type=Path, default=None, help="Path to config.json")
    parser.add_argument("--once", action="store_true", help="Run one check and exit")
    parser.add_argument("--rebaseline", action="store_true",
                        help="Take a fresh baseline (mark current state as known-good)")
    parser.add_argument("--init", action="store_true",
                        help="Detect installed AI apps (LM Studio, Jan, Ollama, ...), "
                             "add them to the config and take a baseline")
    parser.add_argument("--yes", action="store_true",
                        help="With --init: apply without asking")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if args.init:
        # --init may create the config itself (fresh installs).
        return run_init(args.config, args.yes)

    try:
        cfg = load_config(args.config)
    except (OSError, KeyError, ValueError) as err:
        logger.error("Bad config: %s", err)
        return 2

    if args.rebaseline:
        count = fingerprints.accept_current(cfg)
        logger.info("Baseline accepted: %s files marked as known-good", count)
        return 0

    found = run_once(cfg)
    handle(cfg, found)
    resolve_with_user(cfg, found, args.config)

    if args.once:
        return 0

    logger.info("Watching every %s seconds. Ctrl+C to stop.", cfg.interval_seconds)
    try:
        while True:
            time.sleep(cfg.interval_seconds)
            # Re-read the config every cycle: another instance (or the user)
            # may have added watch roots meanwhile. A stale in-memory config
            # would silently unwatch new roots when the user accepts changes.
            try:
                cfg = load_config(args.config)
            except (OSError, KeyError, ValueError) as err:
                logger.error("Config reload failed, keeping previous: %s", err)
            found = run_once(cfg)
            handle(cfg, found)
            resolve_with_user(cfg, found, args.config)
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())