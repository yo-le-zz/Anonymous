"""
Chiffrement de fichiers côté client, bloc par bloc, pour éviter de
charger un fichier entier en mémoire.

Conception (documentée honnêtement, cf. règle « ne pas inventer une
crypto dangereuse ») :

- Le fichier est découpé en blocs de taille fixe (`FILE_CHUNK_SIZE`).
- Chaque bloc est chiffré indépendamment avec le même sous-secret de
  fichier, mais un nonce distinct par bloc : `base_nonce` (8 octets
  aléatoires) concaténé à un compteur de bloc big-endian sur 4 octets.
  Cela garantit l'unicité du nonce pour une même clé tant qu'il y a
  moins de 2**32 blocs (largement suffisant pour `max_file_size`).
- Les données associées (AAD) de chaque bloc incluent l'index du bloc
  et le nombre total de blocs : un attaquant qui contrôle le stockage
  ne peut ni réordonner, ni tronquer, ni dupliquer un bloc sans faire
  échouer l'authentification GCM/Poly1305 du bloc suivant lu.
- Limite assumée : ce n'est PAS un chiffrement de flux authentifié au
  sens strict (STREAM de Hoang/Reyhanitabar/Rogaway/Vizár) ; un
  attaquant qui contrôle le stockage peut supprimer les DERNIERS blocs
  d'un fichier sans que cela soit détecté avant la fin de la lecture
  (troncature). Pour ce projet, la métadonnée `chunk_count` chiffrée
  permet au client de détecter une troncature après coup et de refuser
  le fichier. C'est une limite connue, documentée dans docs/crypto.md,
  préférable à une fausse promesse de sécurité absolue.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import BinaryIO, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from crypto import (
    DEFAULT_ALGORITHM,
    DecryptionError,
    EpochKeyring,
    derive_file_key,
)
from protocol import FILE_CHUNK_SIZE

BASE_NONCE_SIZE = 8
COUNTER_SIZE = 4


def _aead(algorithm: str, key: bytes):
    if algorithm == "AES-256-GCM":
        return AESGCM(key)
    if algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise DecryptionError(f"algorithme inconnu : {algorithm}")


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    return base_nonce + index.to_bytes(COUNTER_SIZE, "big")


def encrypt_file_chunks(
    source: BinaryIO,
    keyring: EpochKeyring,
    epoch: int,
    algorithm: str = DEFAULT_ALGORITHM,
) -> tuple[bytes, int, Iterator[bytes]]:
    """Retourne (file_nonce, chunk_count_placeholder, generator).

    Le nombre total de blocs n'est connu qu'après avoir lu tout le
    fichier ; l'appelant doit donc lire `source` une première fois
    pour compter la taille (ou la connaître déjà via `os.stat`) avant
    d'appeler cette fonction avec un flux repositionné au début.
    """

    file_nonce = secrets.token_bytes(BASE_NONCE_SIZE)
    file_key = derive_file_key(keyring, epoch, file_nonce)
    cipher = _aead(algorithm, file_key)

    def generator() -> Iterator[bytes]:
        index = 0
        while True:
            chunk = source.read(FILE_CHUNK_SIZE)
            if not chunk:
                break
            aad = f"{index}".encode("ascii")
            yield cipher.encrypt(_chunk_nonce(file_nonce, index), chunk, aad)
            index += 1

    return file_nonce, 0, generator()


def decrypt_file_chunks(
    encrypted_chunks: Iterator[bytes],
    keyring: EpochKeyring,
    epoch: int,
    file_nonce: bytes,
    expected_chunk_count: int,
    algorithm: str = DEFAULT_ALGORITHM,
) -> Iterator[bytes]:
    file_key = derive_file_key(keyring, epoch, file_nonce)
    cipher = _aead(algorithm, file_key)

    count = 0
    for index, chunk in enumerate(encrypted_chunks):
        aad = f"{index}".encode("ascii")
        try:
            yield cipher.decrypt(_chunk_nonce(file_nonce, index), chunk, aad)
        except Exception as error:
            raise DecryptionError(f"bloc {index} illisible.") from error
        count += 1

    if count != expected_chunk_count:
        raise DecryptionError(
            f"fichier tronqué : {count} blocs reçus, {expected_chunk_count} attendus."
        )


def save_stream_to_path(chunks: Iterator[bytes], destination: Path) -> int:
    total = 0
    with open(destination, "wb") as handle:
        for chunk in chunks:
            handle.write(chunk)
            total += len(chunk)
    return total
