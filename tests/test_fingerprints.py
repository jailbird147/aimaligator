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


def test_changed_file_backs_up_old_and_diff(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("line1\nline2\n", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.write_text("line1\nEVIL INSTRUCTION\n", encoding="utf-8")
    alerts = fingerprints.check(cfg)
    changed = [a for a in alerts if a.kind == "changed-file"]

    assert changed and "diff saved" in changed[0].detail
    backup_root = tmp_path / "state" / "changed-backups"
    diffs = list(backup_root.rglob("*.diff"))
    assert len(diffs) == 1
    text = diffs[0].read_text(encoding="utf-8")
    assert "EVIL INSTRUCTION" in text and "SKILL.md" in text
    olds = list(backup_root.rglob("old-*"))
    assert b"line2" in olds[0].read_bytes()


def test_repeat_alerts_do_not_spam_backups(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("v1", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.write_text("v2", encoding="utf-8")
    first = fingerprints.check(cfg)
    second = fingerprints.check(cfg)

    first_changed = [a for a in first if a.kind == "changed-file"]
    second_changed = [a for a in second if a.kind == "changed-file"]
    assert "diff saved" in first_changed[0].detail
    assert "diff saved" not in second_changed[0].detail
    backup_root = tmp_path / "state" / "changed-backups"
    assert len(list(backup_root.iterdir())) == 1


def test_accept_resets_backup_memory(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("v1", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.write_text("v2", encoding="utf-8")
    fingerprints.check(cfg)          # backed up once
    fingerprints.accept_current(cfg)  # user accepts
    assert fingerprints.check(cfg) == []

    target.write_text("v3 - again", encoding="utf-8")
    alerts = fingerprints.check(cfg)
    changed = [a for a in alerts if a.kind == "changed-file"]

    assert changed and "diff saved" in changed[0].detail
    diffs = list((tmp_path / "state" / "changed-backups").rglob("*.diff"))
    assert len(diffs) == 2
    assert "v3" in diffs[-1].read_text(encoding="utf-8")


def test_removed_file_backs_up_old_content(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("precious", encoding="utf-8")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.unlink()
    alerts = fingerprints.check(cfg)
    removed = [a for a in alerts if a.kind == "removed-file"]

    assert removed and "old copy saved" in removed[0].detail
    olds = list((tmp_path / "state" / "changed-backups").rglob("old-removed-*"))
    assert olds and olds[0].read_bytes() == b"precious"


def test_binary_change_gets_copies_but_no_diff(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    target = root / "blob.bin"
    target.write_bytes(b"\x00\x01\x02")
    cfg = make_config([root], tmp_path / "state")
    fingerprints.check(cfg)

    target.write_bytes(b"\x00\x09\x09")
    alerts = fingerprints.check(cfg)
    changed = [a for a in alerts if a.kind == "changed-file"]

    assert changed and "binary change" in changed[0].detail
    backup_root = tmp_path / "state" / "changed-backups"
    assert list(backup_root.rglob("*.diff")) == []
    assert list(backup_root.rglob("old-*")) and list(backup_root.rglob("new-*"))


def test_watch_root_can_be_a_single_file(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    cfg = make_config([settings], tmp_path / "state")
    fingerprints.check(cfg)

    settings.write_text("{\"hacked\": true}", encoding="utf-8")
    alerts = fingerprints.check(cfg)

    assert [a.kind for a in alerts] == ["changed-file"]
    assert alerts[0].path == str(settings)
