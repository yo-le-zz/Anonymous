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
    "rooms": {
        "enabled": True,
        "allow_public_rooms": True,
        "max_rooms": 100,
        "max_room_name_length": 64,
        "default_room": "general",
    },
    "logging": {"access_logs": False},
    "ratelimit": {
        "messages_per_minute": 30,
        "uploads_per_minute": 10,
        "sessions_per_minute": 20,
        "max_connections_per_ip": 20,
        # Voir docs/server.md "Anti-spam" : quand activé, une IP qui
        # dépasse la limite subit un cooldown qui double à chaque
        # récidive (1s, 2s, 4s, 8s...) au lieu d'un simple rejet fixe.
        # Explicitement configurable et TOUJOURS annoncé publiquement
        # via /server-info, pour que les clients sachent à quoi
        # s'attendre.
        "progressive_cooldown_enabled": True,
        "progressive_cooldown_max_seconds": 300,
    },
    # Fonctionnalités optionnelles. Certaines sont réellement appliquées
    # par le serveur (reactions/typing, car leur `type` d'enveloppe est
    # visible du serveur sans déchiffrement) ; d'autres sont purement
    # indicatives (replies, room_exchange), car elles vivent entièrement
    # dans le contenu chiffré que le serveur ne peut jamais inspecter.
    # Voir docs/crypto.md pour le détail de cette distinction.
    "features": {
        "reactions_enabled": True,
        "typing_indicators_enabled": True,
        "replies_enabled": True,  # indicatif seulement, voir ci-dessus
        "room_exchange_enabled": True,  # indicatif seulement (mécanisme 100% client)
    },
    # Administration ephémère (voir docs/crypto.md "Administration
    # sans identité") : aucun compte, aucune identité persistante.
    # Si `password_hash` est vide, la PREMIÈRE session qui réclame le
    # rôle l'obtient (jusqu'au redémarrage du serveur). Si un hash est
    # configuré, n'importe quelle session qui fournit le bon mot de
    # passe devient admin — plusieurs sessions peuvent donc être admin
    # simultanément si le mot de passe est partagé, ce qui est voulu.
    "admin": {"password_hash": ""},
    # Bascule fondamentale de confidentialité. Par défaut (true), le
    # serveur ne reçoit et ne peut jamais recevoir de texte en clair
    # (voir docs/crypto.md). Si mis à `false` : le serveur PEUT alors
    # appliquer une modération réelle sur le contenu (voir
    # `[moderation]`), au prix de la confidentialité de bout en bout.
    # Ce mode n'est PAS activé par défaut et doit rester une décision
    # explicite et documentée de l'administrateur (voir docs/privacy.md).
    "privacy": {"e2ee": True},
    "moderation": {
        "banned_words_enabled": False,
        "banned_words_file": "",
    },
    "web": {
        "enabled": True,
        "public_page": True,
        "server_name": "Anonymous Server",
        "description": "",
        "show_online_count": True,
        "show_room_counts": True,
        "show_message_count": True,
        "show_storage_usage": True,
    },
    "temporary": {"enabled": False, "lifetime_seconds": 0},
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

    rooms = config["rooms"]
    if rooms["max_rooms"] <= 0 or rooms["max_room_name_length"] <= 0:
        raise ConfigError("rooms.max_rooms et rooms.max_room_name_length doivent être positifs.")
    if not rooms["default_room"]:
        raise ConfigError("rooms.default_room ne peut pas être vide.")

    ratelimit = config["ratelimit"]
    if ratelimit["progressive_cooldown_max_seconds"] <= 0:
        raise ConfigError("ratelimit.progressive_cooldown_max_seconds doit être positif.")

    moderation = config["moderation"]
    if moderation["banned_words_enabled"] and not moderation["banned_words_file"]:
        raise ConfigError(
            "moderation.banned_words_enabled = true nécessite moderation.banned_words_file."
        )
    if not config["privacy"]["e2ee"] and moderation["banned_words_enabled"]:
        # Autorisé, mais seulement dans ce mode explicite — voir
        # docs/privacy.md. Rien à valider de plus ici : le filtrage
        # réel n'est appliqué que si e2ee = false (voir main.py).
        pass

    temporary = config["temporary"]
    if temporary["enabled"] and temporary["lifetime_seconds"] <= 0:
        raise ConfigError(
            "temporary.enabled = true nécessite temporary.lifetime_seconds > 0."
        )

    web = config["web"]
    if not isinstance(web["server_name"], str) or not web["server_name"].strip():
        raise ConfigError("web.server_name ne peut pas être vide.")


# Champs qui peuvent être rechargés SANS redémarrer le serveur (voir
# `reload_hot_fields` plus bas et docs/server.md "Rechargement à
# chaud"). Tout ce qui touche à l'écoute réseau, au stockage, aux
# sessions ou à l'authentification globale exige un vrai redémarrage :
# les changer à chaud créerait un état incohérent (connexions
# existantes, fichiers déjà ouverts, jetons déjà émis...).
HOT_RELOADABLE_SECTIONS = (
    "messages",
    "retention",
    "files",
    "rooms",
    "ratelimit",
    "features",
    "privacy",
    "moderation",
    "web",
    "logging",
)


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


_config_file_path = _config_path()
_config_file_mtime = _config_file_path.stat().st_mtime if _config_file_path and _config_file_path.exists() else None

# Le chargement au démarrage ne doit JAMAIS faire planter l'import de
# ce module avec une trace Python brute : une commande comme
# `anonymous-server --version` ou `anonymous-server check-config` doit
# pouvoir s'exécuter (et signaler clairement le problème) même si
# server.toml est actuellement invalide. `_load_error` porte l'erreur
# pour que les appelants (CLI, démarrage réel du serveur) décident
# comment réagir ; `Config` retombe sur les valeurs par défaut dans ce
# cas, jamais sur un état à moitié construit.
_load_error: ConfigError | None = None

try:
    Config = load_config()
except ConfigError as _error:
    _load_error = _error
    Config = dict(DEFAULTS)


def config_file_changed() -> bool:
    """Vérification légère (un seul `stat()`) : le fichier de config a-t-il
    changé depuis le dernier chargement ? Utilisé pour la revérification
    périodique en fonctionnement — voir `retention.py`."""

    if _config_file_path is None or not _config_file_path.exists():
        return False

    try:
        current_mtime = _config_file_path.stat().st_mtime
    except OSError:
        return False

    return _config_file_mtime is None or current_mtime != _config_file_mtime


def reload_hot_fields() -> list[str]:
    """Recharge le fichier de configuration et met à jour, EN PLACE
    (`Config` reste le même objet partagé par tous les modules qui ont
    fait `from config import Config`), uniquement les sections listées
    dans `HOT_RELOADABLE_SECTIONS`. Retourne la liste des sections
    effectivement modifiées. Ne touche jamais aux sections qui exigent
    un vrai redémarrage (server, storage, session, auth, crypto,
    network) — si elles ont changé dans le fichier, elles sont
    ignorées et un avertissement doit être journalisé par l'appelant.

    Lève `ConfigError` si le nouveau fichier est invalide : dans ce
    cas, la configuration en mémoire n'est PAS modifiée (on continue
    de tourner avec l'ancienne configuration valide plutôt que de
    planter ou d'appliquer un état incohérent)."""

    global _config_file_mtime

    new_config = load_config()  # valide déjà entièrement le nouveau fichier

    changed_sections = []
    for section in HOT_RELOADABLE_SECTIONS:
        if Config.get(section) != new_config.get(section):
            Config[section] = new_config[section]
            changed_sections.append(section)

    if _config_file_path is not None and _config_file_path.exists():
        _config_file_mtime = _config_file_path.stat().st_mtime

    return changed_sections
