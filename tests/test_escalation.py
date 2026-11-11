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


def test_defender_disabled_reports_honestly(monkeypatch):
    monkeypatch.setattr(escalation, "_defender_service_running", lambda: False)
    monkeypatch.setattr(escalation, "defender_template",
                        lambda: '"mpcmdrun" -Scan -ScanType 3 -File "{path}"')
    cfg = _cfg("defender")

    results = escalation.launch_scan(cfg, [r"C:\x\file.txt"])

    assert len(results) == 1
    assert "Defender is disabled" in results[0][1]


def test_exclude_globs_keep_build_junk_out(tmp_path):
    from aimaligator import fingerprints
    from conftest import make_config as mc

    root = tmp_path / "src"
    (root / "__pycache__").mkdir(parents=True)
    (root / "__pycache__" / "x.pyc").write_bytes(b"junk")
    (root / "pkg.egg-info").mkdir()
    (root / "pkg.egg-info" / "PKG-INFO").write_text("junk", encoding="utf-8")
    (root / "real.py").write_text("print(1)", encoding="utf-8")
    cfg = Config(
        watch_roots=(root,),
        process_markers=(),
        suspicious_children=frozenset(),
        max_hash_bytes=1024 * 1024,
        interval_seconds=300,
        state_dir=tmp_path / "state",
        exclude_globs=("*__pycache__*", "*egg-info*", "*.pyc"),
    )

    hashes = fingerprints.scan_roots(cfg)

    assert set(hashes) == {str(root / "real.py")}


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
