import json

from aimaligator import fingerprints
from aimaligator.main import log_heartbeat, main

from conftest import make_config


def test_heartbeat_written(tmp_path):
    cfg = make_config([], tmp_path / "state")

    log_heartbeat(cfg, [])

    text = (tmp_path / "state" / "checks.log").read_text(encoding="utf-8")
    assert "check ok" in text
    assert "alerts=0" in text


def test_rebaseline_logs_loud_event(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    (root / "SKILL.md").write_text("content", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "watch_roots": [str(root)],
        "state_dir": str(tmp_path / "state"),
    }), encoding="utf-8")

    assert main(["--rebaseline", "--config", str(config_path)]) == 0

    text = (tmp_path / "state" / "alerts.log").read_text(encoding="utf-8")
    assert "baseline-reset" in text
    assert "confirm this was you" in text


def test_heartbeat_not_written_by_rebaseline(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    (root / "SKILL.md").write_text("content", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "watch_roots": [str(root)],
        "state_dir": str(tmp_path / "state"),
    }), encoding="utf-8")

    main(["--rebaseline", "--config", str(config_path)])

    assert not (tmp_path / "state" / "checks.log").exists()
    assert (tmp_path / "state" / "baseline.json").is_file()
