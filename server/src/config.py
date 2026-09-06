"""Chargement et validation de la configuration serveur.

Cherche, dans l'ordre :

1. La variable d'environnement ``ANONYMOUS_SERVER_CONFIG`` (chemin explicite).
2. ``/etc/anonymous/server.toml`` (déploiement .deb / systemd).
3. ``./server.toml`` (développement local).
4. Valeurs par défaut codées ci-dessous.

Toutes les valeurs sont validées : un fichier de config invalide fait
échouer le démarrage avec un message clair plutôt que de démarrer avec
un état incohérent.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


DEFAULTS: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8000},
    "network": {"public_url": ""},
    "auth": {"enabled": False, "password_hash": ""},
    "storage": {
        "database": "./chat.db",
        "files": "./files",
        "max_storage_bytes": 1024 * 1024 * 1024,
    },
    "messages": {"max_size": 10000, "max_messages": 10000},
    "retention": {"enabled": True, "max_age_seconds": 0, "delete_oldest": True},
    "files": {
        "enabled": True,
        "max_file_size": 50 * 1024 * 1024,
        "max_files_per_message": 5,
        "allowed_types": [
            "image/jpeg",
            "image/png",
            "image/webp",
            "video/mp4",
            "video/webm",
            "application/pdf",
        ],
    },
    "crypto": {"key_rotation_messages": 100, "key_rotation_seconds": 3600},
    "session": {"ttl_seconds": 6 * 3600},
    "logging": {"access_logs": False},
    "ratelimit": {
        "messages_per_minute": 30,
        "uploads_per_minute": 10,
        "sessions_per_minute": 20,
        "max_connections_per_ip": 20,
    },
}


class ConfigError(Exception):
    pass


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _config_path() -> Path | None:
    env_path = os.environ.get("ANONYMOUS_SERVER_CONFIG")
    if env_path:
        return Path(env_path)

    etc_path = Path("/etc/anonymous/server.toml")
    if etc_path.exists():
        return etc_path

    local_path = Path("server.toml")
    if local_path.exists():
        return local_path

    return None


def _validate(config: dict) -> None:
    server = config["server"]
    if not isinstance(server["port"], int) or not (0 < server["port"] < 65536):
        raise ConfigError("server.port doit être un entier entre 1 et 65535.")

    storage = config["storage"]
    if storage["max_storage_bytes"] <= 0:
        raise ConfigError("storage.max_storage_bytes doit être positif.")

    messages = config["messages"]
    if messages["max_size"] <= 0 or messages["max_messages"] <= 0:
        raise ConfigError("messages.max_size et messages.max_messages doivent être positifs.")

    retention = config["retention"]
    if retention["max_age_seconds"] < 0:
        raise ConfigError("retention.max_age_seconds ne peut pas être négatif.")

    files = config["files"]
    if files["max_file_size"] <= 0 or files["max_files_per_message"] <= 0:
        raise ConfigError("files.max_file_size et files.max_files_per_message doivent être positifs.")

    auth = config["auth"]
    if auth["enabled"] and not auth["password_hash"]:
        raise ConfigError(
            "auth.enabled = true nécessite auth.password_hash "
            "(générez-le avec : anonymous-server hash-password)."
        )

    crypto = config["crypto"]
    if crypto["key_rotation_messages"] <= 0 or crypto["key_rotation_seconds"] <= 0:
        raise ConfigError("crypto.key_rotation_* doivent être positifs.")

    session = config["session"]
    if session["ttl_seconds"] <= 0:
        raise ConfigError("session.ttl_seconds doit être positif.")


def load_config() -> dict:
    path = _config_path()
    config = dict(DEFAULTS)

    if path is not None:
        try:
            with open(path, "rb") as handle:
                user_config = tomllib.load(handle)
        except tomllib.TOMLDecodeError as error:
            raise ConfigError(f"fichier de configuration invalide ({path}) : {error}") from error

        config = _merge(DEFAULTS, user_config)

    _validate(config)
    return config


Config = load_config()
