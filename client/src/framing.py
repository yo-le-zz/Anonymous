"""Framing longueur-préfixée générique, utilisé pour envoyer/recevoir
un flux de blocs chiffrés de taille variable sans dépendre d'un
format de fichier particulier. Ne contient aucune logique crypto."""

from __future__ import annotations

import struct
from typing import Iterable, Iterator

_HEADER = struct.Struct(">I")  # longueur du bloc, 4 octets big-endian


def frame_chunks(chunks: Iterable[bytes]) -> Iterator[bytes]:
    for chunk in chunks:
        yield _HEADER.pack(len(chunk))
        yield chunk


def unframe_stream(raw_iter: Iterable[bytes]) -> Iterator[bytes]:
    """Consomme un itérable d'octets bruts (de taille arbitraire par
    itération, comme des blocs réseau) et reconstitue les blocs
    encadrés d'origine."""

    buffer = bytearray()
    expected_length: int | None = None

    for piece in raw_iter:
        buffer.extend(piece)

        while True:
            if expected_length is None:
                if len(buffer) < _HEADER.size:
                    break
                (expected_length,) = _HEADER.unpack(bytes(buffer[: _HEADER.size]))
                del buffer[: _HEADER.size]

            if len(buffer) < expected_length:
                break

            yield bytes(buffer[:expected_length])
            del buffer[:expected_length]
            expected_length = None

    if expected_length is not None or buffer:
        raise ValueError("flux tronqué : bloc incomplet.")
