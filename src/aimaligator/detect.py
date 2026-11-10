"""Discovery of installed local-AI apps.

Each detector looks for an app in its default locations and reads the app's
own settings to find its model folder. Detection only *proposes* watch roots
and process markers - the user confirms via ``aimaligator --init``.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Detected:
    """One found application and what should be watched for it."""

    name: str
    roots: list[Path] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)

    def existing_roots(self) -> list[Path]:
        return [r for r in self.roots if r.exists()]


def _home() -> Path:
    return Path(os.environ.get("USERPROFILE") or Path.home())


def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", _home() / "AppData" / "Roaming"))


def _local_appdata() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", _home() / "AppData" / "Local"))


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        logger.debug("Cannot read %s: %s", path, err)
        return {}


def detect_lm_studio() -> Detected | None:
    """LM Studio: skills under ~/.lmstudio, models from its settings.json."""
    home = _home()
    root = home / ".lmstudio"
    settings = root / "settings.json"
    if not root.exists() and not settings.exists():
        return None

    detected = Detected("LM Studio", markers=["lmstudio"])
    if (root / "skills").exists():
        detected.roots.append(root / "skills")
    if (home / ".agents" / "skills").exists():
        detected.roots.append(home / ".agents" / "skills")
    detected.roots.append(settings)

    data = _read_json(settings)
    models = data.get("downloadsFolder")
    if models:
        detected.roots.append(Path(models))
    return detected


def detect_jan() -> Detected:
    """Jan: settings.json points at its data folder; models under llamacpp."""
    appdata_settings = _appdata() / "Jan" / "settings.json"
    data_folder = _read_json(appdata_settings).get("data_folder")
    data = Path(data_folder) if data_folder else _appdata() / "Jan" / "data"

    detected = Detected("Jan", markers=["jan.exe", "\\jan\\"])
    detected.roots += [
        appdata_settings,
        data / "llamacpp" / "models",
        data / "settings.json",
    ]
    return detected


def detect_ollama() -> Detected | None:
    """Ollama: models in OLLAMA_MODELS or ~/.ollama/models."""
    home = _home()
    models = os.environ.get("OLLAMA_MODELS")
    root = home / ".ollama"
    if models:
        models_path = Path(models)
    elif root.exists():
        models_path = root / "models"
    else:
        return None

    detected = Detected("Ollama", markers=["ollama"])
    detected.roots += [root, models_path]
    return detected


def detect_gpt4all() -> Detected | None:
    """GPT4All: data under %LOCALAPPDATA%\\nomic.ai\\GPT4All."""
    root = _local_appdata() / "nomic.ai" / "GPT4All"
    if not root.exists():
        return None
    detected = Detected("GPT4All", markers=["gpt4all"])
    detected.roots += [root, root / "models"]
    return detected


def detect_generic_runners() -> Detected | None:
    """koboldcpp / llama-server / llamafile - watch their default homes."""
    candidates = [
        _home() / ".cache" / "llama.cpp",
        _local_appdata() / "KoboldCpp",
        _local_appdata() / "Programs" / "KoboldCpp",
    ]
    existing = [c for c in candidates if c.exists()]
    if not existing:
        return None
    return Detected(
        "llama.cpp family",
        roots=existing,
        markers=["koboldcpp", "llama-server", "llamafile"],
    )


def detect_all() -> list[Detected]:
    """Run every detector, skipping apps that are not installed."""
    found: list[Detected] = []
    for detector in (
        detect_lm_studio,
        detect_jan,
        detect_ollama,
        detect_gpt4all,
        detect_generic_runners,
    ):
        try:
            app = detector()
        except Exception as err:  # a broken detector must not kill --init
            logger.warning("Detector %s failed: %s", detector.__name__, err)
            continue
        if app is not None and app.existing_roots():
            found.append(app)
    return found