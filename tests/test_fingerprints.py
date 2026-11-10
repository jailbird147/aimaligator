from aimaligator import fingerprints

from conftest import make_config


def test_first_run_creates_baseline_and_no_alerts(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    (root / "SKILL.md").write_text("hello", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")

    alerts = fingerprints.check(cfg)

    assert alerts and alerts[0].kind == "info"
    assert (tmp_path / "state" / "baseline.json").is_file()


def test_new_file_alerts(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)  # baseline

    (root / "new.md").write_text("sneaky", encoding="utf-8")
    alerts = fingerprints.check(cfg)

    kinds = [a.kind for a in alerts]
    assert kinds == ["new-file"]
    assert alerts[0].path == str(root / "new.md")


def test_changed_file_alerts_repeat_until_accepted(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("v1", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.write_text("v2 - evil instructions", encoding="utf-8")
    first = fingerprints.check(cfg)
    assert [a.kind for a in first] == ["changed-file"]

    # The baseline is NOT auto-updated: an unresolved change keeps alerting.
    second = fingerprints.check(cfg)
    assert [a.kind for a in second] == ["changed-file"]

    # After the user accepts the current state, the alerting stops.
    fingerprints.accept_current(cfg)
    third = fingerprints.check(cfg)
    assert third == []


def test_removed_file_alerts(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("data", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.unlink()
    alerts = fingerprints.check(cfg)

    assert [a.kind for a in alerts] == ["removed-file"]


def test_oversized_file_uses_stat_fingerprint(tmp_path):
    big = tmp_path / "model.gguf"
    with big.open("wb") as fh:
        fh.truncate(2 * 1024 * 1024)  # sparse 2 MB file, above the 1 MB cap
    cfg = make_config([tmp_path], tmp_path / "state")

    fingerprint = fingerprints.fingerprint_of(big, cfg.max_hash_bytes)

    assert fingerprint is not None
    assert fingerprint.startswith("stat:")


def test_changed_oversized_file_alerts(tmp_path):
    big = tmp_path / "model.gguf"
    with big.open("wb") as fh:
        fh.truncate(2 * 1024 * 1024)
    cfg = make_config([tmp_path], tmp_path / "state")
    fingerprints.check(cfg)

    # Rewrite the file so its size and modification time both change.
    big.write_bytes(b"x" * (2 * 1024 * 1024 + 123))
    alerts = fingerprints.check(cfg)

    assert [a.kind for a in alerts] == ["changed-file"]


def test_key_files_identified_by_name_without_creating_them(tmp_path):
    # NOTE: never actually create files with key names here - some security
    # software kills processes that touch files named like SSH keys.
    for name in ("id_ed25519", "id_rsa", "id_ecdsa", "server.key", "cert.pem"):
        assert fingerprints.is_key_file(tmp_path / name)
    assert not fingerprints.is_key_file(tmp_path / "skill.md")
    assert not fingerprints.is_key_file(tmp_path / "model.gguf")


def test_key_files_use_stat_fingerprint_not_content(tmp_path, monkeypatch):
    small = tmp_path / "ordinary.txt"
    small.write_text("hello", encoding="utf-8")
    cfg = make_config([tmp_path], tmp_path / "state")
    monkeypatch.setattr(
        fingerprints, "is_key_file", lambda p: p.name == "ordinary.txt"
    )

    fingerprint = fingerprints.fingerprint_of(small, cfg.max_hash_bytes)

    assert fingerprint is not None
    assert fingerprint.startswith("stat:")


def test_watch_root_can_be_a_single_file(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    cfg = make_config([settings], tmp_path / "state")
    fingerprints.check(cfg)

    settings.write_text("{\"hacked\": true}", encoding="utf-8")
    alerts = fingerprints.check(cfg)

    assert [a.kind for a in alerts] == ["changed-file"]
    assert alerts[0].path == str(settings)
