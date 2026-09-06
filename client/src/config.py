"""Configuration locale du client Anonymous.

Le fichier de config du client ne contient que des préférences
d'interface (aucun secret : les secrets vivent dans rooms.json /
servers.json via storage.py, avec des permissions restrictives
dédiées)."""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

from storage import data_home

DEFAULT_CONFIG = {
    "ui": {
        "theme": "default",
    },
    "network": {
        "connect_timeout_seconds": 5,
        "reconnect_backoff_seconds": 2,
        "reconnect_backoff_max_seconds": 30,
        "max_download_size_bytes": 100 * 1024 * 1024,
    },
}


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict:
    config_path = data_home() / "client.toml"

    if not config_path.exists():
        return DEFAULT_CONFIG

    try:
        with open(config_path, "rb") as handle:
            user_config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return DEFAULT_CONFIG

    return _merge(DEFAULT_CONFIG, user_config)


Config = load_config()
