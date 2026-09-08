"""
Modèles Pydantic de l'enveloppe opaque échangée avec les clients.

Le serveur valide UNIQUEMENT la forme du payload (tailles, champs
attendus) : il n'a ni la capacité ni le besoin de comprendre son
contenu. Aucun champ d'identité permanente (username, client_id,
owner, ip...) n'existe dans ces modèles.

`session_id` et `signature` (voir `SignedEnvelopeIn`) ne sont PAS des
identités permanentes : `session_id` désigne une session éphémère en
RAM (session.py) qui expire et disparaît au redémarrage, et
`signature` ne fait que prouver que l'expéditeur possède la clé
privée Ed25519 associée à CETTE session — exactement ce qu'il faut
pour empêcher l'usurpation, rien de plus.
"""

from __future__ import annotations

import base64

from pydantic import BaseModel, Field

ALLOWED_TYPES = {"msg", "file", "kx"}
ALLOWED_ALGORITHMS = {"AES-256-GCM", "ChaCha20-Poly1305"}

import re

_ROOM_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def is_valid_room_name(name: str, max_length: int) -> bool:
    return bool(name) and len(name) <= max_length and bool(_ROOM_NAME_RE.match(name))


def b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def canonical_envelope_bytes(
    protocol_version: int, type_: str, algorithm: str, key_id: str, nonce: str, ciphertext: str
) -> bytes:
    """Octets exacts signés par le client (voir crypto.py côté client,
    fonction du même nom). Toute modification de cette fonction doit
    être répercutée à l'identique côté client, sous peine de casser la
    vérification de signature pour tout le monde."""

    return f"{protocol_version}|{type_}|{algorithm}|{key_id}|{nonce}|{ciphertext}".encode("utf-8")


class EnvelopeIn(BaseModel):
    protocol_version: int = Field(ge=1, le=1)
    type: str
    algorithm: str
    key_id: str = Field(min_length=1, max_length=256)
    nonce: str = Field(min_length=1, max_length=64)
    ciphertext: str = Field(min_length=1)

    def validate_semantics(self, max_size: int) -> None:
        if self.type not in ALLOWED_TYPES:
            raise ValueError(f"type inconnu : {self.type}")

        if self.algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(f"algorithme inconnu : {self.algorithm}")

        if len(self.ciphertext) > max_size:
            raise ValueError("message trop volumineux.")


class SignedEnvelopeIn(EnvelopeIn):
    """Enveloppe + preuve de provenance de session (voir docs/crypto.md
    §"Session éphémère et signature"). `session_id` et `signature`
    concernent uniquement la vérification anti-usurpation ; ils ne
    sont jamais stockés en base (seul `anonymous_number`, dérivé de la
    session au moment de l'acceptation, est stocké — voir database.py).

    `room` désigne le CANAL public côté serveur (comme un salon IRC),
    pas une identité. `room_password` (en clair, uniquement transmis le
    temps de la requête HTTPS) n'est jamais stocké ni journalisé — seul
    son hash Argon2id l'est, dans la table `rooms`, au moment de la
    création du salon. Ni `room` ni `room_password` ne font partie des
    octets signés (voir `canonical_envelope_bytes`) : ce sont des
    paramètres de routage/autorisation, pas une preuve d'identité de
    l'expéditeur."""

    session_id: str = Field(min_length=1, max_length=128)
    signature: str = Field(min_length=1, max_length=256)
    room: str = Field(default="general", min_length=1, max_length=64)
    room_password: str | None = Field(default=None, max_length=1024)

    def canonical_bytes(self) -> bytes:
        return canonical_envelope_bytes(
            self.protocol_version, self.type, self.algorithm, self.key_id, self.nonce, self.ciphertext
        )


class SessionRequest(BaseModel):
    public_key: str = Field(min_length=1, max_length=64)


class RoomCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    password: str | None = Field(default=None, max_length=1024)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
