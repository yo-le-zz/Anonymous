"""
Anonymous Crypto Protocol v1
=============================

Ce module implémente le protocole cryptographique décrit dans
``docs/crypto.md``. Il ne fait AUCUN appel réseau : toute la
cryptographie est locale au client.

Primitives utilisées (toutes via `cryptography`, pas de crypto maison) :

- Ed25519              : signature des messages par la session éphémère
                          (identité visuelle "Anonymous #XXXXXX"),
                          jamais réutilisée d'une session à l'autre.
- X25519                : établissement d'un secret partagé (ECDH),
                          utilisé uniquement lors de l'échange
                          d'invitation d'un salon ("room exchange").
- HKDF-SHA256           : dérivation de clés (secret de salon -> clé
                          d'epoch, clé d'epoch -> sous-clé de fichier ;
                          secret ECDH -> secret de salon).
- AES-256-GCM
  ou ChaCha20-Poly1305   : chiffrement authentifié des messages/fichiers.
- secrets.token_bytes    : génération de tout secret aléatoire.

Chaque primitive a un rôle strictement séparé (voir docs/crypto.md,
section "Séparation des rôles cryptographiques") : la clé de session
Ed25519 ne sert jamais à chiffrer, la clé X25519 ne sert jamais à
signer, etc.

Le serveur ne voit jamais : le secret de salon, les clés dérivées,
les clés privées X25519/Ed25519, ou le texte en clair. Le serveur voit
la clé PUBLIQUE Ed25519 d'une session (nécessaire pour vérifier ses
signatures), mais uniquement en RAM et jamais associée à une identité
permanente — voir server/src/session.py et docs/privacy.md.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import secrets
import time
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# ============================================================
# CONSTANTES DE PROTOCOLE
# ============================================================

PROTOCOL_VERSION = 1

ALGO_AES256GCM = "AES-256-GCM"
ALGO_CHACHA20POLY1305 = "ChaCha20-Poly1305"

DEFAULT_ALGORITHM = ALGO_AES256GCM

NONCE_SIZE = 12  # 96 bits, requis par AES-GCM et ChaCha20-Poly1305
ROOM_SECRET_SIZE = 32
KEY_SIZE = 32

_HKDF_ROOM_INFO = b"anonymous-chat-v1|room-secret"
_HKDF_EPOCH_INFO = b"anonymous-chat-v1|epoch-key"
_HKDF_FILE_INFO = b"anonymous-chat-v1|file-key"

INVITE_PREFIX = "anon1"  # format d'invite : anon1:<room_id_b64>:<secret_b64>


class DecryptionError(Exception):
    """Levée quand un ciphertext ne peut pas être déchiffré avec les
    clés actuellement connues du client (mauvaise clé/epoch, message
    corrompu, ou secret de salon inconnu)."""


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64e(data: bytes) -> str:
    """Version publique de `_b64e`, pour encoder des clés publiques et
    signatures Ed25519 avant de les envoyer au serveur."""

    return _b64e(data)


def b64d(data: str) -> bytes:
    """Version publique de `_b64d`."""

    return _b64d(data)


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = KEY_SIZE) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _aead(algorithm: str, key: bytes):
    if algorithm == ALGO_AES256GCM:
        return AESGCM(key)
    if algorithm == ALGO_CHACHA20POLY1305:
        return ChaCha20Poly1305(key)
    raise DecryptionError(f"algorithme inconnu : {algorithm}")


# ============================================================
# ROOM SECRET (secret de salon, jamais envoyé au serveur)
# ============================================================

@dataclasses.dataclass(frozen=True)
class Room:
    """Un salon = un identifiant public (non secret, sert juste à
    distinguer les invites) + un secret partagé. Le room_id n'est
    jamais envoyé au serveur ; il ne sert qu'à la dérivation de clé
    et à l'affichage local."""

    room_id: bytes
    secret: bytes

    def fingerprint(self) -> str:
        """Empreinte courte à comparer verbalement entre participants
        pour détecter une invitation altérée (aucune garantie contre
        un attaquant actif tant que la comparaison n'est pas faite
        par un canal indépendant)."""

        digest = hashlib.sha256(self.room_id + self.secret).hexdigest()
        return " ".join(digest[i : i + 4] for i in range(0, 16, 4))

    def to_invite(self) -> str:
        return f"{INVITE_PREFIX}:{_b64e(self.room_id)}:{_b64e(self.secret)}"

    @staticmethod
    def from_invite(invite: str) -> "Room":
        invite = invite.strip()
        parts = invite.split(":")

        if len(parts) != 3 or parts[0] != INVITE_PREFIX:
            raise ValueError("Format d'invite invalide.")

        room_id = _b64d(parts[1])
        secret = _b64d(parts[2])

        if len(secret) != ROOM_SECRET_SIZE:
            raise ValueError("Secret de salon invalide.")

        return Room(room_id=room_id, secret=secret)

    @staticmethod
    def create_new() -> "Room":
        return Room(
            room_id=secrets.token_bytes(8),
            secret=secrets.token_bytes(ROOM_SECRET_SIZE),
        )


# ============================================================
# ROTATION DES CLÉS PAR EPOCH
# ============================================================

@dataclasses.dataclass
class RotationPolicy:
    max_messages: int = 100
    max_seconds: int = 3600


class EpochKeyring:
    """Dérive et met en cache les clés symétriques par epoch pour un
    salon donné. Une epoch est un simple compteur entier ; la clé de
    l'epoch N est dérivée du secret de salon, jamais réutilisée pour
    autre chose, et les nonces AEAD sont toujours tirés aléatoirement
    (jamais réutilisés avec une même clé grâce à la taille de 96 bits
    et au faible volume de messages par epoch imposé par la rotation).
    """

    def __init__(self, room: Room, policy: RotationPolicy | None = None):
        self.room = room
        self.policy = policy or RotationPolicy()
        self._cache: dict[int, bytes] = {}
        self._current_epoch = 0
        self._messages_in_epoch = 0
        self._epoch_started_at = time.monotonic()

    def _derive(self, epoch: int) -> bytes:
        if epoch not in self._cache:
            self._cache[epoch] = _hkdf(
                ikm=self.room.secret,
                salt=self.room.room_id,
                info=_HKDF_EPOCH_INFO + b"|" + str(epoch).encode("ascii"),
            )
        return self._cache[epoch]

    def key_for_epoch(self, epoch: int) -> bytes:
        return self._derive(epoch)

    def current_epoch(self) -> int:
        """Fait avancer l'epoch courante si la politique de rotation
        (nombre de messages ou durée) est atteinte, puis la retourne."""

        elapsed = time.monotonic() - self._epoch_started_at

        if (
            self._messages_in_epoch >= self.policy.max_messages
            or elapsed >= self.policy.max_seconds
        ):
            self._current_epoch += 1
            self._messages_in_epoch = 0
            self._epoch_started_at = time.monotonic()

        return self._current_epoch

    def note_message_sent(self) -> None:
        self._messages_in_epoch += 1

    def forget_before(self, epoch: int) -> None:
        """Purge volontairement les clés d'epochs révolues de la
        mémoire du processus (limite l'exposition si le processus
        client est compromis après coup). Optionnel : appelé par le
        client quand il le juge utile."""

        for key in list(self._cache):
            if key < epoch:
                del self._cache[key]


# ============================================================
# ENVELOPPE DE MESSAGE
# ============================================================

@dataclasses.dataclass
class Envelope:
    """Représentation locale d'un payload tel qu'il transite sur le
    réseau. Ne contient jamais d'identité : uniquement ce qu'il faut
    pour décoder le ciphertext."""

    protocol_version: int
    type: Literal["msg", "file", "kx"]
    algorithm: str
    key_id: str
    nonce: str
    ciphertext: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Envelope":
        return Envelope(
            protocol_version=int(data["protocol_version"]),
            type=data["type"],
            algorithm=data["algorithm"],
            key_id=data["key_id"],
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
        )


def _key_id(room: Room, epoch: int) -> str:
    return f"{_b64e(room.room_id)}.{epoch}"


def _parse_key_id(key_id: str) -> tuple[str, int]:
    room_id_b64, _, epoch = key_id.rpartition(".")
    return room_id_b64, int(epoch)


def parse_key_id(key_id: str) -> tuple[str, int]:
    """Version publique de `_parse_key_id`, utilisable par le reste du
    client (ex. pour retrouver l'epoch d'un message de type "file")."""

    return _parse_key_id(key_id)


def encrypt_message(
    keyring: EpochKeyring,
    plaintext: bytes,
    algorithm: str = DEFAULT_ALGORITHM,
    envelope_type: Literal["msg", "file"] = "msg",
) -> Envelope:
    epoch = keyring.current_epoch()
    key = keyring.key_for_epoch(epoch)

    nonce = secrets.token_bytes(NONCE_SIZE)

    aad = f"{PROTOCOL_VERSION}|{algorithm}|{envelope_type}".encode("ascii")

    ciphertext = _aead(algorithm, key).encrypt(nonce, plaintext, aad)

    keyring.note_message_sent()

    return Envelope(
        protocol_version=PROTOCOL_VERSION,
        type=envelope_type,
        algorithm=algorithm,
        key_id=_key_id(keyring.room, epoch),
        nonce=_b64e(nonce),
        ciphertext=_b64e(ciphertext),
    )


def decrypt_message(keyring: EpochKeyring, envelope: Envelope) -> bytes:
    if envelope.protocol_version != PROTOCOL_VERSION:
        raise DecryptionError("version de protocole non supportée.")

    room_id_b64, epoch = _parse_key_id(envelope.key_id)

    if room_id_b64 != _b64e(keyring.room.room_id):
        raise DecryptionError("ce message appartient à un autre salon.")

    key = keyring.key_for_epoch(epoch)

    aad = f"{envelope.protocol_version}|{envelope.algorithm}|{envelope.type}".encode("ascii")

    try:
        plaintext = _aead(envelope.algorithm, key).decrypt(
            _b64d(envelope.nonce),
            _b64d(envelope.ciphertext),
            aad,
        )
    except Exception as error:
        raise DecryptionError("échec du déchiffrement.") from error

    return plaintext


# ============================================================
# ÉCHANGE X25519 (invitation d'un salon sans partager le secret
# directement en clair via un canal potentiellement observé)
# ============================================================

@dataclasses.dataclass
class KeyExchangeState:
    exchange_id: bytes
    private_key: X25519PrivateKey

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes_raw()


def start_key_exchange() -> KeyExchangeState:
    return KeyExchangeState(
        exchange_id=secrets.token_bytes(8),
        private_key=X25519PrivateKey.generate(),
    )


def finish_key_exchange(state: KeyExchangeState, peer_public_bytes: bytes) -> Room:
    """Calcule le secret ECDH partagé puis en dérive un secret de
    salon. Les deux parties (celle qui a initié l'échange et celle
    qui y répond) obtiennent le même résultat car X25519 est
    commutatif : ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub).

    Limite documentée : sans vérification indépendante des clés
    publiques échangées (ex. comparaison vocale de l'empreinte), un
    relais actif pourrait théoriquement substituer les clés
    publiques (attaque de l'homme du milieu). Comparez toujours
    l'empreinte du salon obtenu par un second canal avant de faire
    confiance à un salon issu d'un échange."""

    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = state.private_key.exchange(peer_public_key)

    room_secret = _hkdf(
        ikm=shared_secret,
        salt=state.exchange_id,
        info=_HKDF_ROOM_INFO,
    )

    return Room(room_id=state.exchange_id, secret=room_secret)


# ============================================================
# CLÉ DE FICHIER (dérivée de l'epoch, indépendante du contenu)
# ============================================================

def derive_file_key(keyring: EpochKeyring, epoch: int, file_nonce: bytes) -> bytes:
    """Dérive une clé dédiée pour le chiffrement en flux (par bloc)
    d'un fichier, à partir de la clé de l'epoch courante. `file_nonce`
    identifie le fichier de façon unique côté client (aléatoire,
    jamais réutilisé, jamais renvoyé au serveur en clair sous une
    forme reliant plusieurs fichiers entre eux)."""

    epoch_key = keyring.key_for_epoch(epoch)

    return _hkdf(
        ikm=epoch_key,
        salt=file_nonce,
        info=_HKDF_FILE_INFO,
    )


# ============================================================
# SESSION ÉPHÉMÈRE ET SIGNATURE (Ed25519)
# ============================================================
#
# Rôle strictement séparé du chiffrement des messages (AES/ChaCha) et
# de l'établissement du secret de salon (X25519) : cette clé ne sert
# QU'À prouver, auprès du serveur, que les messages envoyés sur une
# session donnée proviennent bien de la même source, afin que le
# serveur puisse attribuer un numéro pseudonyme "Anonymous #XXXXXX" à
# cette session et détecter toute tentative d'usurpation.
#
# Cycle de vie volontairement différent de celui du secret de salon :
# - le secret de salon (Room) est persisté localement (fichier
#   0600) car on veut pouvoir déchiffrer l'historique après un
#   redémarrage du client ;
# - la clé de signature Ed25519, elle, n'est JAMAIS écrite sur disque.
#   Elle est régénérée en mémoire à chaque nouvel établissement de
#   session (typiquement à chaque `/connect`), ce qui garantit
#   qu'aucune session ne peut être reliée à une autre après coup, y
#   compris par le client lui-même.

class SigningIdentity:
    """Identité de signature Ed25519 purement éphémère. Générée en
    mémoire, jamais persistée, jamais réutilisée d'une session à
    l'autre. Perdre le processus client (fermeture, crash) fait
    disparaître cette clé : c'est voulu, voir docs/privacy.md."""

    def __init__(self):
        self._private_key = Ed25519PrivateKey.generate()

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


def canonical_envelope_bytes(envelope: Envelope) -> bytes:
    """Octets EXACTS signés par le client pour prouver la provenance
    de session d'un message. Doit rester identique, au caractère près,
    à `canonical_envelope_bytes` côté serveur (server/src/protocol.py)
    — sinon toute vérification de signature échoue."""

    return (
        f"{envelope.protocol_version}|{envelope.type}|{envelope.algorithm}|"
        f"{envelope.key_id}|{envelope.nonce}|{envelope.ciphertext}"
    ).encode("utf-8")


def admin_canonical_bytes(*parts: str) -> bytes:
    """Octets signés pour une action admin (voir docs/crypto.md
    "Administration sans identité"). Doit rester identique, au
    caractère près, à `admin_canonical_bytes` côté serveur
    (server/src/protocol.py)."""

    return "|".join(["admin", *parts]).encode("utf-8")


def verify_signature_offline(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Utilitaire de test/diagnostic côté client : permet de vérifier
    localement qu'une signature produite par une `SigningIdentity` est
    valide, sans dépendre du serveur. N'est pas utilisé par le
    protocole réseau lui-même (le client fait confiance à sa propre
    signature ; c'est le serveur qui vérifie celles des autres)."""

    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
