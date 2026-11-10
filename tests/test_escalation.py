from pathlib import Path

from aimaligator import escalation
from aimaligator.config import Config


def _cfg(scan_command: str) -> Config:
    return Config(
        watch_roots=(),
        process_markers=(),
        suspicious_children=frozenset(),
        max_hash_bytes=1024 * 1024,
        interval_seconds=300,
        state_dir=Path("."),
        scan_command=scan_command,
    )


def test_scan_command_none_never_launches_anything():
    cfg = _cfg("none")
    results = escalation.launch_scan(cfg, [r"C:\x\file.txt"])

    assert len(results) == 1
    assert "no scanner configured" in results[0][1]


def test_defender_template_contains_placeholder_and_flags():
    template = escalation.defender_template()
    if template is None:  # machine without Defender
        return
    assert "MpCmdRun" in template
    assert "{path}" in template
    assert "-ScanType 3" in template


def test_custom_template_launches_and_reports(tmp_path):
    cfg = _cfg('cmd /c echo {path}')
    target = tmp_path / "somefile.txt"
    target.write_text("x", encoding="utf-8")

    results = escalation.launch_scan(cfg, [str(target)])

    assert len(results) == 1
    assert "pid" in results[0][1]
