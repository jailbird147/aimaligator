from aimaligator import main as main_mod
from aimaligator.alerts import Alert
from aimaligator.main import handle

from conftest import make_config


def test_handle_auto_scan_scans_once_per_change(tmp_path):
    target = tmp_path / "changed.txt"
    target.write_text("v1", encoding="utf-8")
    cfg = make_config([], tmp_path / "state", auto_scan=True, scan_command="none")

    found = [Alert("changed-file", str(target), "changed")]
    scanned = handle(cfg, found)

    assert str(target) in scanned
    log = (tmp_path / "state" / "alerts.log").read_text(encoding="utf-8")
    assert "auto-escalated" in log

    # same unchanged file again: no rescan, no new auto-escalated lines
    scanned2 = handle(cfg, found)
    assert scanned2 == set()
    assert log.count("auto-escalated") == 1


def test_handle_without_auto_scan_never_scans(tmp_path):
    target = tmp_path / "changed.txt"
    target.write_text("v1", encoding="utf-8")
    cfg = make_config([], tmp_path / "state", auto_scan=False, scan_command="none")

    scanned = handle(cfg, [Alert("changed-file", str(target), "changed")])

    assert scanned == set()
    log = (tmp_path / "state" / "alerts.log").read_text(encoding="utf-8")
    assert "auto-escalated" not in log


def test_handle_silent_toast_flag_reaches_toast(tmp_path, monkeypatch):
    cfg = make_config([], tmp_path / "state", silent_notifications=True,
                      scan_command="none")
    seen = {}

    def fake_send_toast(title, body, silent=False):
        seen["silent"] = silent
        return True

    monkeypatch.setattr(main_mod.alerts_mod, "send_toast", fake_send_toast)
    handle(cfg, [Alert("new-file", str(tmp_path / "x.txt"), "appeared")])

    assert seen["silent"] is True


def test_handle_loud_toast_by_default(tmp_path, monkeypatch):
    cfg = make_config([], tmp_path / "state", silent_notifications=False,
                      scan_command="none")
    seen = {}

    def fake_send_toast(title, body, silent=False):
        seen["silent"] = silent
        return True

    monkeypatch.setattr(main_mod.alerts_mod, "send_toast", fake_send_toast)
    handle(cfg, [Alert("new-file", str(tmp_path / "x.txt"), "appeared")])

    assert seen["silent"] is False


def test_resolve_n_skips_already_scanned(tmp_path, monkeypatch):
    cfg = make_config([], tmp_path / "state", scan_command="none")
    target = tmp_path / "t.txt"
    target.write_text("x", encoding="utf-8")
    found = [Alert("changed-file", str(target), "changed")]

    main_mod._is_interactive = lambda: True
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    handle(cfg, found, )  # auto_scan off, so nothing scanned here
    resolve_calls = []

    def fake_launch(cfg2, paths):
        resolve_calls.append(list(paths))
        return [(p, "no scanner configured") for p in paths]

    monkeypatch.setattr(main_mod.escalation, "launch_scan", fake_launch)
    main_mod.resolve_with_user(cfg, found, scanned={str(target)})

    assert resolve_calls == [[]]  # already scanned this cycle: nothing doubled
