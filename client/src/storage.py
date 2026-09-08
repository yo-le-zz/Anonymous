"""
Stockage local des secrets du client Anonymous.

RÈGLE ABSOLUE : aucune clé privée, aucun secret de salon, ne quitte
jamais ce dossier local. Rien de ce qui est écrit ici n'est envoyé au
serveur.

Emplacement (respecte la spécification XDG Base Directory) :

    $XDG_DATA_HOME/anonymous/          (par défaut ~/.local/share/anonymous/)

Permissions :

    dossier   -> 0700
    secrets   -> 0600
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from crypto import Room

DIR_MODE = 0o700
FILE_MODE = 0o600


def data_home() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")

    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".local" / "share"

    return base / "anonymous"


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)

    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass


def _write_secret(path: Path, content: str) -> None:
    _ensure_dir(path.parent)

    # Écriture avec permissions restrictives dès la création, pour
    # éviter toute fenêtre où le fichier serait lisible par d'autres
    # utilisateurs du système.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, FILE_MODE)

    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
    finally:
        try:
            os.chmod(path, FILE_MODE)
        except OSError:
            pass


def _check_permissions_warning(path: Path) -> str | None:
    """Retourne un avertissement si les permissions du fichier sont
    plus permissives que prévu (utile après une restauration de
    sauvegarde ou un montage sur un système de fichiers exotique)."""

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None

    if mode & 0o077:
        return (
            f"Attention : {path} a des permissions trop larges ({oct(mode)}). "
            "Recommandé : chmod 600."
        )

    return None


class ClientStore:
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or data_home()
        _ensure_dir(self.base_dir)

    # -------------------- rooms --------------------

    @property
    def rooms_file(self) -> Path:
        return self.base_dir / "rooms.json"

    def load_rooms(self) -> dict[str, Room]:
        path = self.rooms_file

        if not path.exists():
            return {}

        warning = _check_permissions_warning(path)
        if warning:
            print(warning)

        try:
            raw = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

        rooms: dict[str, Room] = {}

        for name, entry in raw.items():
            try:
                rooms[name] = Room.from_invite(entry["invite"])
            except (KeyError, ValueError):
                continue

        return rooms

    def _load_raw_rooms(self) -> dict:
        path = self.rooms_file

        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def get_room_password(self, name: str) -> str | None:
        """Mot de passe de SALON côté serveur (contrôle d'accès au
        canal), distinct du secret de chiffrement de bout en bout. Lu
        depuis le même fichier local protégé (0600) que les invitations
        — voir docs/crypto.md pour la distinction entre les deux."""

        entry = self._load_raw_rooms().get(name)
        return entry.get("server_password") if entry else None

    def save_room(self, name: str, room: Room, server_password: str | None = None) -> None:
        """Enregistre le secret de salon (E2EE) et, optionnellement, le
        mot de passe de SALON côté serveur pour ce nom. Si
        `server_password` n'est pas fourni, un mot de passe déjà
        enregistré pour ce nom est conservé tel quel."""

        raw = self._load_raw_rooms()
        existing_password = raw.get(name, {}).get("server_password") if name in raw else None

        raw[name] = {
            "invite": room.to_invite(),
            "server_password": server_password if server_password is not None else existing_password,
        }

        _write_secret(self.rooms_file, json.dumps(raw, indent=2))

    def delete_room(self, name: str) -> bool:
        raw = self._load_raw_rooms()

        if name not in raw:
            return False

        del raw[name]
        _write_secret(self.rooms_file, json.dumps(raw, indent=2))
        return True

    # -------------------- servers --------------------

    @property
    def servers_file(self) -> Path:
        return self.base_dir / "servers.json"

    def load_servers(self) -> dict[str, dict]:
        path = self.servers_file

        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def save_server(self, name: str, url: str, room_name: str | None) -> None:
        servers = self.load_servers()
        servers[name] = {"url": url, "room": room_name}
        _write_secret(self.servers_file, json.dumps(servers, indent=2))

    # -------------------- downloads --------------------

    @property
    def downloads_dir(self) -> Path:
        path = self.base_dir / "downloads"
        _ensure_dir(path)
        return path
