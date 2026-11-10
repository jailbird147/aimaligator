from pathlib import Path

from aimaligator import detect


def test_detect_ollama_absent_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    assert detect.detect_ollama() is None


def test_detect_ollama_from_home(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    (tmp_path / ".ollama" / "models").mkdir(parents=True)

    app = detect.detect_ollama()

    assert app is not None and app.name == "Ollama"
    assert tmp_path / ".ollama" / "models" in app.roots
    assert "ollama" in app.markers


def test_detect_ollama_honours_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # no .ollama here
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "bigdisk" / "ollama"))
    (tmp_path / "bigdisk" / "ollama").mkdir(parents=True)

    app = detect.detect_ollama()

    assert app is not None
    assert tmp_path / "bigdisk" / "ollama" in app.roots


def test_detect_jan_reads_data_folder_setting(tmp_path, monkeypatch):
    appdata = tmp_path / "appdata"
    monkeypatch.setenv("APPDATA", str(appdata))
    (appdata / "Jan").mkdir(parents=True)
    (appdata / "Jan" / "settings.json").write_text(
        '{"data_folder": "F:\\\\Jan"}', encoding="utf-8"
    )

    app = detect.detect_jan()

    assert app.name == "Jan"
    assert Path(r"F:\Jan\llamacpp\models") in app.roots
    assert Path(r"F:\Jan\settings.json") in app.roots
    assert appdata / "Jan" / "settings.json" in app.roots


def test_detect_lm_studio_reads_models_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    root = tmp_path / ".lmstudio"
    (root / "skills").mkdir(parents=True)
    (root / "settings.json").write_text(
        '{"downloadsFolder": "F:\\\\LMStudio\\\\models"}', encoding="utf-8"
    )

    app = detect.detect_lm_studio()

    assert app is not None and app.name == "LM Studio"
    assert Path(r"F:\LMStudio\models") in app.roots
    assert root / "skills" in app.roots


def test_detect_all_skips_missing_apps(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)

    assert detect.detect_all() == []
