from aimaligator import alerts as alerts_mod
from aimaligator.alerts import Alert


def test_as_line_contains_all_fields():
    alert = Alert(kind="changed-file", path=r"C:\x\SKILL.md", detail="contents changed")
    line = alert.as_line()

    assert "changed-file" in line
    assert r"C:\x\SKILL.md" in line
    assert "contents changed" in line


def test_append_alerts_writes_lines(tmp_path):
    state = tmp_path / "state"
    found = [
        Alert(kind="new-file", path=r"C:\a", detail="appeared"),
        Alert(kind="removed-file", path=r"C:\b", detail="gone"),
    ]

    log_path = alerts_mod.append_alerts(state, found)

    text = log_path.read_text(encoding="utf-8")
    assert text.count("\n") == 2
    assert "new-file | C:\\a" in text


def test_send_toast_missing_script_returns_false(monkeypatch):
    monkeypatch.setattr(alerts_mod, "TOAST_SCRIPT_NAME", "definitely-missing.ps1")
    assert alerts_mod.send_toast("t", "b") is False
