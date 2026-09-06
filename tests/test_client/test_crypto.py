"""Tests du protocole cryptographique client.

Isolation sys.path / sys.modules : client/src et server/src définissent
tous les deux des modules nommés `config`, `protocol`, `storage`
(noms génériques, cohérents avec la structure de projet demandée,
mais qui entreraient en collision si les deux étaient importés sous
le même nom dans le même processus). On purge donc `sys.modules` et on
force `sys.path` à ne contenir QUE `client/src` avant d'importer quoi
que ce soit ici. `tests/test_server/test_server.py` fait le miroir
exact pour le côté serveur.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENT_SRC = str(ROOT / "client" / "src")
SERVER_SRC = str(ROOT / "server" / "src")

_COLLIDING_NAMES = (
    "config", "main", "protocol", "storage", "crypto", "media",
    "framing", "database", "auth", "ratelimit", "retention",
)
for _name in _COLLIDING_NAMES:
    sys.modules.pop(_name, None)

sys.path = [p for p in sys.path if p != SERVER_SRC]
if CLIENT_SRC not in sys.path:
    sys.path.insert(0, CLIENT_SRC)

os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="anonymous-client-test-")

import crypto  # noqa: E402
import framing  # noqa: E402
import media  # noqa: E402
import protocol  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402


def make_room() -> crypto.Room:
    return crypto.Room.create_new()


def test_invite_roundtrip():
    room = make_room()
    imported = crypto.Room.from_invite(room.to_invite())
    assert imported.room_id == room.room_id
    assert imported.secret == room.secret


def test_encrypt_decrypt_roundtrip():
    room = make_room()
    keyring = crypto.EpochKeyring(room)

    envelope = crypto.encrypt_message(keyring, protocol.TextPayload(body="salut le monde").encode())
    plaintext = crypto.decrypt_message(crypto.EpochKeyring(room), envelope)

    assert protocol.TextPayload.decode(plaintext).body == "salut le monde"


def test_decrypt_wrong_room_fails():
    room_a = make_room()
    room_b = make_room()

    keyring_a = crypto.EpochKeyring(room_a)
    envelope = crypto.encrypt_message(keyring_a, b"secret")

    keyring_b = crypto.EpochKeyring(room_b)
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_message(keyring_b, envelope)


def test_decrypt_wrong_nonce_fails():
    room = make_room()
    keyring = crypto.EpochKeyring(room)
    envelope = crypto.encrypt_message(keyring, b"secret")

    tampered = crypto.Envelope(**{**envelope.to_dict(), "nonce": envelope.nonce[:-2] + "AA"})
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_message(keyring, tampered)


def test_decrypt_wrong_ciphertext_fails():
    room = make_room()
    keyring = crypto.EpochKeyring(room)
    envelope = crypto.encrypt_message(keyring, b"secret")

    tampered_ct = envelope.ciphertext[:-2] + ("AA" if envelope.ciphertext[-2:] != "AA" else "BB")
    tampered = crypto.Envelope(**{**envelope.to_dict(), "ciphertext": tampered_ct})
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_message(keyring, tampered)


def test_key_rotation_advances_epoch():
    room = make_room()
    keyring = crypto.EpochKeyring(room, crypto.RotationPolicy(max_messages=2, max_seconds=99999))

    epoch_before = keyring.current_epoch()
    keyring.note_message_sent()
    keyring.note_message_sent()
    epoch_after = keyring.current_epoch()

    assert epoch_after == epoch_before + 1


def test_old_epoch_key_still_derivable_but_distinct():
    room = make_room()
    keyring = crypto.EpochKeyring(room, crypto.RotationPolicy(max_messages=1, max_seconds=99999))

    key_epoch_0 = keyring.key_for_epoch(0)
    keyring.note_message_sent()
    key_epoch_1 = keyring.key_for_epoch(keyring.current_epoch())

    assert key_epoch_0 != key_epoch_1


def test_x25519_exchange_produces_matching_room():
    state_a = crypto.start_key_exchange()
    state_b = crypto.KeyExchangeState(
        exchange_id=state_a.exchange_id, private_key=X25519PrivateKey.generate()
    )

    room_from_a = crypto.finish_key_exchange(state_a, state_b.public_bytes())
    room_from_b = crypto.finish_key_exchange(state_b, state_a.public_bytes())

    assert room_from_a.secret == room_from_b.secret
    assert room_from_a.fingerprint() == room_from_b.fingerprint()


def test_x25519_exchange_different_peers_diverge():
    state_a = crypto.start_key_exchange()
    state_b = crypto.KeyExchangeState(
        exchange_id=state_a.exchange_id, private_key=X25519PrivateKey.generate()
    )
    mallory = X25519PrivateKey.generate()

    room_from_a = crypto.finish_key_exchange(state_a, state_b.public_bytes())
    room_with_mallory = crypto.finish_key_exchange(
        state_a, mallory.public_key().public_bytes_raw()
    )

    assert room_from_a.secret != room_with_mallory.secret


def test_file_chunk_encrypt_decrypt_roundtrip():
    room = make_room()
    keyring = crypto.EpochKeyring(room)
    epoch = keyring.current_epoch()

    data = os.urandom(1024 * 1024 * 2 + 777)
    file_nonce, _, chunks = media.encrypt_file_chunks(io.BytesIO(data), keyring, epoch)
    encrypted = list(chunks)

    decrypted = b"".join(
        media.decrypt_file_chunks(iter(encrypted), keyring, epoch, file_nonce, len(encrypted))
    )
    assert decrypted == data


def test_file_chunk_tampering_detected():
    room = make_room()
    keyring = crypto.EpochKeyring(room)
    epoch = keyring.current_epoch()

    data = os.urandom(1024 * 1024 + 5)
    file_nonce, _, chunks = media.encrypt_file_chunks(io.BytesIO(data), keyring, epoch)
    encrypted = list(chunks)
    encrypted[0] = bytes([encrypted[0][0] ^ 0xFF]) + encrypted[0][1:]

    with pytest.raises(crypto.DecryptionError):
        b"".join(
            media.decrypt_file_chunks(iter(encrypted), keyring, epoch, file_nonce, len(encrypted))
        )


def test_file_chunk_truncation_detected():
    room = make_room()
    keyring = crypto.EpochKeyring(room)
    epoch = keyring.current_epoch()

    data = os.urandom(1024 * 1024 * 3)
    file_nonce, _, chunks = media.encrypt_file_chunks(io.BytesIO(data), keyring, epoch)
    encrypted = list(chunks)

    with pytest.raises(crypto.DecryptionError):
        b"".join(
            media.decrypt_file_chunks(
                iter(encrypted[:-1]), keyring, epoch, file_nonce, len(encrypted)
            )
        )


def test_framing_roundtrip_with_arbitrary_network_slicing():
    chunks = [os.urandom(100), os.urandom(0) or b"x", os.urandom(50000)]
    framed = b"".join(framing.frame_chunks(iter(chunks)))

    def slice_weird(data, size):
        for i in range(0, len(data), size):
            yield data[i : i + size]

    result = list(framing.unframe_stream(slice_weird(framed, 13)))
    assert result == chunks


def test_normalize_server_url_and_ws_conversion():
    assert protocol.normalize_server_url("example.org:8000") == "http://example.org:8000"
    assert protocol.normalize_server_url("https://example.org/") == "https://example.org"

    assert protocol.build_ws_url("http://host:8000") == "ws://host:8000/ws"
    assert protocol.build_ws_url("https://host") == "wss://host/ws"

    assert protocol.is_insecure("http://host") is True
    assert protocol.is_insecure("https://host") is False
