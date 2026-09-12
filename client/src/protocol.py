"""
Structures du contenu en clair échangé UNE FOIS déchiffré localement,
et constantes du protocole réseau (chemins HTTP/WS, tailles de bloc).

Rien dans ce module n'est jamais envoyé au serveur en clair : le
serveur ne voit que des `Envelope` (voir crypto.py), jamais les
structures ci-dessous.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Literal

FILE_CHUNK_SIZE = 1024 * 1024  # 1 Mo par bloc chiffré indépendamment

WS_PATH = "/ws"
HTTP_MESSAGES_PATH = "/messages"
HTTP_UPLOAD_PATH = "/files"
HTTP_DOWNLOAD_PATH = "/files/{file_id}"
HTTP_SERVER_INFO_PATH = "/server-info"


@dataclasses.dataclass
class TextPayload:
    kind: Literal["text"] = "text"
    body: str = ""
    # Référence à un message existant (voir /reply). Purement
    # indicative et *jamais* vérifiée par le serveur : il n'a pas le
    # texte en clair, donc pas de moyen de vérifier que la référence
    # est cohérente. Ce n'est qu'un confort d'affichage côté client
    # (voir docs/crypto.md, "Fonctionnalités indicatives").
    reply_to: int | None = None

    def encode(self) -> bytes:
        return json.dumps(
            {"kind": self.kind, "body": self.body, "reply_to": self.reply_to}
        ).encode("utf-8")

    @staticmethod
    def decode(data: bytes) -> "TextPayload":
        parsed = json.loads(data.decode("utf-8"))
        return TextPayload(body=parsed.get("body", ""), reply_to=parsed.get("reply_to"))


@dataclasses.dataclass
class ReactionPayload:
    """Une réaction est un mini-message chiffré à part entière (type
    d'enveloppe `reaction`), référençant l'id du message ciblé. Le
    serveur voit le TYPE (pour appliquer `[features] reactions_enabled`)
    mais jamais l'émoji ni la cible : les deux sont chiffrés."""

    kind: Literal["reaction"] = "reaction"
    emoji: str = ""
    target_id: int = 0

    def encode(self) -> bytes:
        return json.dumps(
            {"kind": self.kind, "emoji": self.emoji, "target_id": self.target_id}
        ).encode("utf-8")

    @staticmethod
    def decode(data: bytes) -> "ReactionPayload":
        parsed = json.loads(data.decode("utf-8"))
        return ReactionPayload(emoji=parsed.get("emoji", ""), target_id=parsed.get("target_id", 0))


@dataclasses.dataclass
class FileMetadataPayload:
    """Métadonnées chiffrées d'un fichier. Le nom réel et le type ne
    sont jamais connus du serveur : seul un `file_id` aléatoire
    (attribué par le serveur au moment de l'upload, sans lien avec le
    contenu) permet de retrouver les blocs chiffrés."""

    kind: Literal["file"] = "file"
    file_id: str = ""
    filename: str = ""
    mime_type: str = ""
    size_bytes: int = 0
    chunk_count: int = 0
    file_nonce: str = ""  # base64, sert de sel de dérivation de clé

    def encode(self) -> bytes:
        return json.dumps(dataclasses.asdict(self)).encode("utf-8")

    @staticmethod
    def decode(data: bytes) -> "FileMetadataPayload":
        parsed = json.loads(data.decode("utf-8"))
        return FileMetadataPayload(**{**parsed, "kind": "file"})


def build_ws_url(base_http_url: str, room: str | None = None, room_password: str | None = None) -> str:
    """Convertit une URL http(s) de serveur en URL ws(s), en respectant
    la règle : http -> ws, https -> wss. Ne force jamais TLS : c'est à
    l'utilisateur de choisir https:// s'il veut du TLS (typiquement via
    un reverse proxy, voir docs/https.md).

    `room`/`room_password` sont ajoutés en paramètres de requête pour
    que le serveur sache à quel salon abonner cette connexion (voir
    docs/crypto.md — ce ne sont pas des identifiants d'utilisateur,
    juste un routage de diffusion)."""

    if base_http_url.startswith("https://"):
        url = "wss://" + base_http_url[len("https://") :] + WS_PATH
    elif base_http_url.startswith("http://"):
        url = "ws://" + base_http_url[len("http://") :] + WS_PATH
    else:
        raise ValueError("L'URL du serveur doit commencer par http:// ou https://")

    params = {}
    if room:
        params["room"] = room
    if room_password:
        params["room_password"] = room_password

    if params:
        from urllib.parse import urlencode

        url = f"{url}?{urlencode(params)}"

    return url


def normalize_server_url(raw: str) -> str:
    raw = raw.strip()

    if not raw:
        raise ValueError("URL vide.")

    if not raw.startswith("http://") and not raw.startswith("https://"):
        # Par défaut on suppose http:// pour un usage local/LAN, mais on
        # avertit toujours l'utilisateur (voir main.py) quand ce n'est
        # pas du https://.
        raw = "http://" + raw

    return raw.rstrip("/")


def is_insecure(server_url: str) -> bool:
    return server_url.startswith("http://")
