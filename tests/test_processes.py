from pathlib import Path

from aimaligator import processes

from conftest import make_config


class FakeProc:
    def __init__(self, pid, name, exe, kids=None):
        self.pid = pid
        self.name = name
        self.exe = exe
        self._kids = kids or []

    def children(self, recursive=True):
        return self._kids


def test_is_suspicious_matches_with_and_without_exe():
    suspicious = frozenset({"certutil", "bitsadmin"})
    assert processes.is_suspicious("certutil.exe", suspicious)
    assert processes.is_suspicious("CERTUTIL", suspicious)
    assert not processes.is_suspicious("certutility.exe", suspicious)
    assert not processes.is_suspicious("notepad.exe", suspicious)


def test_children_of_only_returns_children_of_marker_parents():
    child = FakeProc(2, "cmd.exe", r"C:\Windows\System32\cmd.exe")
    parent = FakeProc(1, "LM Studio.exe", r"C:\lmstudio\LM Studio.exe", [child])
    unrelated = FakeProc(3, "chrome.exe", r"C:\chrome.exe", [FakeProc(4, "x.exe", "x.exe")])

    pairs = processes.children_of([parent, unrelated], ("lmstudio",))

    assert [(p.pid, n) for p, n in pairs] == [(2, "cmd.exe")]


def test_check_flags_suspicious_child():
    child = FakeProc(2, "certutil.exe", r"C:\Windows\System32\certutil.exe")
    parent = FakeProc(1, "node.exe", r"C:\Users\demo\.lmstudio\bin\node.exe", [child])

    cfg = make_config([], Path("."))
    alerts = processes.check(cfg, procs=[parent])

    assert len(alerts) == 1
    assert alerts[0].kind == "suspicious-child"
    assert "certutil" in alerts[0].path


def test_child_alerts_allowlist_policy():
    from conftest import make_config
    from pathlib import Path

    cfg = make_config(
        [], Path("."),
        child_policy="allowlist",
        allowed_children={"node", "python"},
    )

    assert processes.child_alerts(cfg, "node.exe") == []
    assert processes.child_alerts(cfg, "NODE") == []
    assert len(processes.child_alerts(cfg, "curl.exe")) == 1
    assert len(processes.child_alerts(cfg, "totally-unknown.exe")) == 1


def test_child_alerts_suspicious_only_policy():
    from conftest import make_config
    from pathlib import Path

    cfg = make_config([], Path("."))  # default: suspicious-only

    assert processes.child_alerts(cfg, "certutil.exe")
    assert processes.child_alerts(cfg, "totally-unknown.exe") == []


def test_check_uses_allowlist_policy(tmp_path):
    child = FakeProc(2, "weird-downloader.exe", r"C:\tmp\weird-downloader.exe")
    parent = FakeProc(1, "LM Studio.exe", r"C:\lmstudio\LM Studio.exe", [child])

    cfg = make_config(
        [], tmp_path / "state",
        child_policy="allowlist",
        allowed_children={"node", "python"},
    )
    alerts = processes.check(cfg, procs=[parent])

    assert len(alerts) == 1
    assert "allowlist policy" in alerts[0].detail


def test_attr_value_handles_real_psutil_process():
    import psutil

    me = psutil.Process()
    name = processes._attr_value(me, "name")

    assert isinstance(name, str)
    assert "python" in name.lower()


def test_check_ignores_benign_children():
    child = FakeProc(2, "notepad.exe", r"C:\Windows\notepad.exe")
    parent = FakeProc(1, "LM Studio.exe", r"C:\lmstudio\LM Studio.exe", [child])

    cfg = make_config([], Path("."))
    assert processes.check(cfg, procs=[parent]) == []
