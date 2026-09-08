"""Tests d'intégration du serveur Anonymous.

Isolation de sys.path / sys.modules : voir la note en tête de
tests/test_client/test_crypto.py — le même principe s'applique ici en
sens inverse pour ne jamais importer accidentellement les modules du
client (client/src a aussi un config.py, protocol.py, storage.py...).
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import json
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

sys.path = [p for p in sys.path if p != CLIENT_SRC]
if SERVER_SRC not in sys.path:
    sys.path.insert(0, SERVER_SRC)

# Configuration de test écrite AVANT tout import de `config` (qui se
# charge au moment de l'import du module).
_TEST_DIR = Path(tempfile.mkdtemp(prefix="anonymous-server-test-"))
_DB_PATH = _TEST_DIR / "chat.db"
_FILES_DIR = _TEST_DIR / "files"

_TOML = f"""
[server]
host = "127.0.0.1"
port = 8000

[storage]
database = "{_DB_PATH.as_posix()}"
files = "{_FILES_DIR.as_posix()}"
max_storage_bytes = 100000

[messages]
max_size = 2000
max_messages = 5

[retention]
enabled = true
max_age_seconds = 0
delete_oldest = true

[files]
enabled = true
max_file_size = 500
max_files_per_message = 5

[crypto]
key_rotation_messages = 100
key_rotation_seconds = 3600

[rooms]
enabled = true
allow_public_rooms = true
max_rooms = 1000
max_room_name_length = 64
default_room = "general"

[logging]
access_logs = false

[ratelimit]
messages_per_minute = 1000
uploads_per_minute = 1000
sessions_per_minute = 100000
max_connections_per_ip = 20
"""

_config_path = _TEST_DIR / "server.toml"
_config_path.write_text(_TOML)
os.environ["ANONYMOUS_SERVER_CONFIG"] = str(_config_path)

import auth  # noqa: E402
import database  # noqa: E402
import main  # noqa: E402
import protocol as server_protocol  # noqa: E402
import session as session_module  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

FORBIDDEN_COLUMNS = {
    "owner", "client_token", "owner_token_hash", "user_id", "client_id",
    "ip", "username", "session_id", "public_key",
}


def _b64e(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class SignedClient:
    """Simule un client Anonymous réel : établit une session éphémère
    (nouvelle paire Ed25519, jamais persistée) puis signe chaque
    message envoyé, exactement comme le fait client/src/main.py."""

    def __init__(self, client: TestClient, headers: dict | None = None):
        self.client = client
        self.headers = headers or {}
        self.private_key = Ed25519PrivateKey.generate()

        public_key_b64 = _b64e(self.private_key.public_key().public_bytes_raw())
        response = client.post(
            "/session", json={"public_key": public_key_b64}, headers=self.headers
        )
        response.raise_for_status()
        data = response.json()
        self.session_id = data["session_id"]
        self.anonymous_number = data["anonymous_number"]

    def _sign(self, envelope: dict, session_id: str | None = None) -> dict:
        message_bytes = server_protocol.canonical_envelope_bytes(
            envelope["protocol_version"],
            envelope["type"],
            envelope["algorithm"],
            envelope["key_id"],
            envelope["nonce"],
            envelope["ciphertext"],
        )
        signature = self.private_key.sign(message_bytes)

        body = dict(envelope)
        body["session_id"] = session_id or self.session_id
        body["signature"] = _b64e(signature)
        return body

    def post_message(self, envelope: dict, impersonate_session_id: str | None = None):
        body = self._sign(envelope, session_id=impersonate_session_id)
        return self.client.post("/messages", json=body, headers=self.headers)


def make_envelope(text: str = "hello") -> dict:
    return {
        "protocol_version": 1,
        "type": "msg",
        "algorithm": "AES-256-GCM",
        "key_id": "abc.0",
        "nonce": "AAAAAAAAAAAAAAAA",
        "ciphertext": text * 4,
    }


def test_health():
    with TestClient(main.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_create_and_fetch_message():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        response = sender.post_message(make_envelope("abcXYZ123456"))
        assert response.status_code == 200
        body = response.json()

        assert set(body.keys()) == {
            "id", "protocol_version", "type", "algorithm", "key_id", "nonce",
            "ciphertext", "created_at", "anonymous_number", "room",
        }
        assert body["anonymous_number"] == sender.anonymous_number
        for forbidden in FORBIDDEN_COLUMNS:
            assert forbidden not in body

        history = client.get("/messages").json()["messages"]
        assert any(m["id"] == body["id"] for m in history)


def test_broadcast_over_websocket():
    with TestClient(main.app) as client:
        sender = SignedClient(client)

        with client.websocket_connect("/ws") as ws:
            response = sender.post_message(make_envelope("broadcastme12"))
            assert response.status_code == 200

            event = ws.receive_json()
            assert event["type"] == "message_created"
            assert event["envelope"]["ciphertext"] == "broadcastme12" * 4
            assert event["envelope"]["anonymous_number"] == sender.anonymous_number


def test_invalid_envelope_rejected():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        bad = make_envelope()
        bad["type"] = "not-a-real-type"
        response = sender.post_message(bad)
        assert response.status_code == 422


def test_message_too_large_rejected():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        bad = make_envelope("x" * 5000)
        response = sender.post_message(bad)
        assert response.status_code == 422


def test_message_without_session_rejected():
    with TestClient(main.app) as client:
        # Requête bien formée mais avec un session_id inventé de toutes
        # pièces (jamais enregistré via /session).
        sender = SignedClient(client)
        response = sender.post_message(make_envelope("nosession123"), impersonate_session_id="fabriqué-au-hasard")
        assert response.status_code == 401


def test_retention_delete_oldest():
    # max_messages = 5 dans la config de test.
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        ids = []
        for i in range(8):
            response = sender.post_message(make_envelope(f"msgnum{i:03d}"))
            ids.append(response.json()["id"])

        import retention

        retention.run_retention_once(
            main.Config["retention"], main.Config["messages"], main.file_storage
        )

        remaining = [m["id"] for m in client.get("/messages", params={"limit": 100}).json()["messages"]]
        assert len(remaining) <= 5
        # Les plus anciens doivent avoir disparu, les plus récents rester.
        assert ids[-1] in remaining
        assert ids[0] not in remaining


def test_retention_max_age():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        response = sender.post_message(make_envelope("oldmessage12"))
        message_id = response.json()["id"]

        # Recule artificiellement le timestamp pour simuler l'ancienneté
        # (les clients ne peuvent jamais faire ça : c'est un utilitaire
        # de test qui écrit directement en base).
        connection = database._connection()
        with database.transaction():
            connection.execute(
                "UPDATE messages SET created_at = ? WHERE id = ?",
                (time.time() - 1000, message_id),
            )

        import retention

        retention_config = dict(main.Config["retention"])
        retention_config["max_age_seconds"] = 10
        retention.run_retention_once(retention_config, main.Config["messages"], main.file_storage)

        assert database.get_message(message_id) is None


def test_auth_required_when_enabled():
    main.Config["auth"]["enabled"] = True
    main.Config["auth"]["password_hash"] = auth.hash_password("correct-horse")

    try:
        with TestClient(main.app) as client:
            # Impossible d'établir une session sans le mot de passe serveur.
            response = client.post(
                "/session", json={"public_key": _b64e(Ed25519PrivateKey.generate().public_key().public_bytes_raw())}
            )
            assert response.status_code == 401

            login = client.post("/auth/login", json={"password": "wrong"})
            assert login.status_code == 401

            login = client.post("/auth/login", json={"password": "correct-horse"})
            assert login.status_code == 200
            token = login.json()["token"]
            headers = {"Authorization": f"Bearer {token}"}

            sender = SignedClient(client, headers=headers)
            response = sender.post_message(make_envelope("shouldwork12"))
            assert response.status_code == 200

            # L'historique doit AUSSI être protégé par le mot de passe
            # serveur : sinon la protection n'aurait de sens que pour
            # l'écriture, pas la lecture.
            unauthenticated_history = client.get("/messages")
            assert unauthenticated_history.status_code == 401

            authenticated_history = client.get("/messages", headers=headers)
            assert authenticated_history.status_code == 200
    finally:
        main.Config["auth"]["enabled"] = False
        main.Config["auth"]["password_hash"] = ""


def test_upload_download_roundtrip():
    with TestClient(main.app) as client:
        payload = os.urandom(200)
        response = client.post(
            "/files", content=payload, headers={"Content-Type": "application/octet-stream"}
        )
        assert response.status_code == 200
        file_id = response.json()["file_id"]
        assert response.json()["size_bytes"] == 200

        download = client.get(f"/files/{file_id}")
        assert download.status_code == 200
        assert download.content == payload


def test_upload_too_large_rejected():
    with TestClient(main.app) as client:
        payload = os.urandom(2000)  # max_file_size = 500 dans la config de test
        response = client.post(
            "/files", content=payload, headers={"Content-Type": "application/octet-stream"}
        )
        assert response.status_code == 413


def test_download_unknown_file_404():
    with TestClient(main.app) as client:
        response = client.get("/files/does-not-exist")
        assert response.status_code == 404


def test_file_path_traversal_rejected():
    import storage as server_storage

    fs = server_storage.FileStorage(str(_FILES_DIR), 500, 100000)
    for malicious in ("../evil", "a/b", "..\\evil", ".."):
        try:
            fs._path_for(malicious)
            assert False, f"aurait dû échouer pour {malicious!r}"
        except ValueError:
            pass


def test_privacy_schema_has_no_identity_columns():
    connection = database._connection()

    for table in ("messages", "files"):
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        assert columns.isdisjoint(FORBIDDEN_COLUMNS), (
            f"colonne interdite trouvée dans {table} : {columns & FORBIDDEN_COLUMNS}"
        )

    # Seule table liée aux messages : `messages` et `files`. Aucune
    # table `sessions` persistée quelque part (les sessions ne vivent
    # qu'en RAM, voir session.py).
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "sessions" not in tables
    assert not any("session" in t.lower() for t in tables)


def test_two_clients_same_room_unlinkable():
    """Deux enveloppes envoyées avec le même key_id (même salon, même
    epoch) ne partagent, dans le schéma stocké, aucun champ qui
    permettrait de les relier à une identité réelle ou permanente. Le
    seul champ commun visible entre deux messages d'une même session
    est `anonymous_number`, qui est un pseudonyme de session temporaire
    documenté (voir database.py), pas une identité réelle."""

    with TestClient(main.app) as client:
        alice = SignedClient(client)
        bob = SignedClient(client)

        r1 = alice.post_message(make_envelope("fromclientA1")).json()
        r2 = bob.post_message(make_envelope("fromclientB2")).json()

        for message in (r1, r2):
            assert FORBIDDEN_COLUMNS.isdisjoint(message.keys())

        assert r1["key_id"] == r2["key_id"] == "abc.0"
        assert r1["anonymous_number"] != r2["anonymous_number"]


# ============================================================
# TESTS DEMANDÉS EXPLICITEMENT — IDENTITÉ ÉPHÉMÈRE DE SESSION
# ============================================================

def test_two_sessions_get_different_numbers_and_ids():
    with TestClient(main.app) as client:
        alice = SignedClient(client)
        bob = SignedClient(client)

        assert alice.session_id != bob.session_id
        assert alice.anonymous_number != bob.anonymous_number


def test_reconnecting_client_gets_a_new_identity():
    """Un même « client » (ici : le même test, simulant une
    reconnexion) qui établit une nouvelle session obtient un nouveau
    session_id et — avec une probabilité écrasante — un nouveau
    numéro. Rien ne permet de relier les deux sessions entre elles."""

    with TestClient(main.app) as client:
        first = SignedClient(client)
        second = SignedClient(client)

        assert first.session_id != second.session_id
        assert first.anonymous_number != second.anonymous_number

        # Le client ne peut pas non plus se servir de son ANCIENNE clé
        # privée pour signer sous le NOUVEAU session_id : chaque
        # session est bien liée à SA PROPRE clé publique.
        message = make_envelope("oldkeynewsession")
        forged_body = first._sign(message, session_id=second.session_id)
        response = client.post("/messages", json=forged_body)
        assert response.status_code == 401


def test_impersonation_is_rejected():
    """Client A obtient Anonymous #NNNNNN. Client B, qui ne connaît
    pas la clé privée de A, tente d'envoyer un message en se faisant
    passer pour la session de A (même session_id). Le serveur doit
    refuser : la signature de B ne correspond pas à la clé publique
    enregistrée pour la session de A."""

    with TestClient(main.app) as client:
        client_a = SignedClient(client)
        client_b = SignedClient(client)

        assert client_a.anonymous_number != client_b.anonymous_number

        forged = client_b.post_message(
            make_envelope("usurpation"), impersonate_session_id=client_a.session_id
        )
        assert forged.status_code == 401

        # Le message légitime de A, lui, doit toujours fonctionner.
        legit = client_a.post_message(make_envelope("legit-message"))
        assert legit.status_code == 200
        assert legit.json()["anonymous_number"] == client_a.anonymous_number


def test_server_restart_invalidates_sessions():
    """Simule un redémarrage serveur : un nouveau SessionRegistry (RAM
    vide) ne connaît plus les sessions établies avant lui, exactement
    comme un vrai redémarrage de processus."""

    with TestClient(main.app) as client:
        sender = SignedClient(client)
        assert main.session_registry.get(sender.session_id) is not None

    fresh_registry_after_restart = session_module.SessionRegistry(ttl_seconds=6 * 3600)
    assert fresh_registry_after_restart.get(sender.session_id) is None


def test_logs_never_contain_session_id_or_public_key(caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        with TestClient(main.app) as client:
            sender = SignedClient(client)
            sender.post_message(make_envelope("watch-the-logs"))

    all_log_text = "\n".join(record.getMessage() for record in caplog.records)

    assert sender.session_id not in all_log_text
    assert _b64e(sender.private_key.public_key().public_bytes_raw()) not in all_log_text


# ============================================================
# SALONS (rooms) — publics, privés, listing, isolation
# ============================================================

def envelope_for_room(room: str, text: str = "hello") -> dict:
    env = make_envelope(text)
    env["room"] = room
    return env


def test_message_defaults_to_general_room():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        response = sender.post_message(make_envelope("defaultroom12"))
        assert response.status_code == 200
        assert response.json()["room"] == "general"


def test_posting_to_new_room_auto_creates_it_public():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        response = sender.post_message(envelope_for_room("brandnewroom", "firstmsg1234"))
        assert response.status_code == 200
        assert response.json()["room"] == "brandnewroom"

        rooms = client.get("/rooms").json()["rooms"]
        found = next(r for r in rooms if r["name"] == "brandnewroom")
        assert found["has_password"] is False
        assert found["message_count"] == 1


def test_create_private_room_requires_password_to_post():
    with TestClient(main.app) as client:
        create = client.post("/rooms", json={"name": "secretroom", "password": "hunter2"})
        assert create.status_code == 200
        assert create.json()["has_password"] is True

        sender = SignedClient(client)

        body = sender._sign(envelope_for_room("secretroom", "nopassword123"))
        # Pas de room_password fourni du tout.
        response = client.post("/messages", json=body)
        assert response.status_code == 401

        body_wrong = sender._sign(envelope_for_room("secretroom", "wrongpass1234"))
        body_wrong["room_password"] = "wrong-password"
        response = client.post("/messages", json=body_wrong)
        assert response.status_code == 401

        body_right = sender._sign(envelope_for_room("secretroom", "rightpass1234"))
        body_right["room_password"] = "hunter2"
        response = client.post("/messages", json=body_right)
        assert response.status_code == 200
        assert response.json()["room"] == "secretroom"


def test_create_duplicate_room_conflict():
    with TestClient(main.app) as client:
        first = client.post("/rooms", json={"name": "dupe-room", "password": None})
        assert first.status_code == 200

        second = client.post("/rooms", json={"name": "dupe-room", "password": None})
        assert second.status_code == 409


def test_invalid_room_name_rejected():
    with TestClient(main.app) as client:
        response = client.post("/rooms", json={"name": "has spaces!!", "password": None})
        assert response.status_code == 422


def test_room_creation_disabled_when_allow_public_rooms_false():
    main.Config["rooms"]["allow_public_rooms"] = False
    try:
        with TestClient(main.app) as client:
            response = client.post("/rooms", json={"name": "shouldfailroom", "password": None})
            assert response.status_code == 403

            # Poster dans un salon qui n'existe pas encore doit aussi
            # échouer, puisque la création libre est désactivée.
            sender = SignedClient(client)
            response = sender.post_message(envelope_for_room("unknownroom", "willfail12345"))
            assert response.status_code == 404
    finally:
        main.Config["rooms"]["allow_public_rooms"] = True


def test_rooms_disabled_ignores_room_field():
    main.Config["rooms"]["enabled"] = False
    try:
        with TestClient(main.app) as client:
            sender = SignedClient(client)
            response = sender.post_message(envelope_for_room("whatever-room", "ignored12345"))
            assert response.status_code == 200
            # Quand les salons sont désactivés, tout retombe sur le
            # salon par défaut de la configuration, quel que soit ce
            # que le client a demandé.
            assert response.json()["room"] == main.Config["rooms"]["default_room"]
    finally:
        main.Config["rooms"]["enabled"] = True


def test_room_password_never_logged_or_stored_in_plaintext(caplog):
    import logging

    with caplog.at_level(logging.DEBUG):
        with TestClient(main.app) as client:
            client.post("/rooms", json={"name": "watched-room", "password": "super-secret-pw"})
            sender = SignedClient(client)
            body = sender._sign(envelope_for_room("watched-room", "checklog1234"))
            body["room_password"] = "super-secret-pw"
            client.post("/messages", json=body)

    all_log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "super-secret-pw" not in all_log_text

    row = database.get_room("watched-room")
    assert row["password_hash"] != "super-secret-pw"
    assert row["password_hash"].startswith("$argon2")


def test_history_is_scoped_per_room():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        sender.post_message(envelope_for_room("room-a", "messageinA12"))
        sender.post_message(envelope_for_room("room-b", "messageinB12"))

        history_a = client.get("/messages", params={"room": "room-a"}).json()["messages"]
        history_b = client.get("/messages", params={"room": "room-b"}).json()["messages"]

        assert all(m["room"] == "room-a" for m in history_a)
        assert all(m["room"] == "room-b" for m in history_b)
        assert not any(m["ciphertext"] == "messageinB12" * 4 for m in history_a)


def test_websocket_broadcast_is_scoped_per_room():
    """Vérifie l'isolation sans jamais attendre indéfiniment une
    absence de message (le transport de test ne propose pas de
    réception avec timeout) : on vérifie plutôt que chaque connexion
    ne reçoit QUE les messages de son propre salon, dans le bon ordre,
    ce qu'une fuite vers le mauvais salon casserait immédiatement."""

    with TestClient(main.app) as client:
        sender = SignedClient(client)

        with client.websocket_connect("/ws?room=room-a") as ws_a, \
             client.websocket_connect("/ws?room=room-b") as ws_b:

            posted_a1 = sender.post_message(envelope_for_room("room-a", "roomAfirst123")).json()
            event = ws_a.receive_json()
            assert event["envelope"]["id"] == posted_a1["id"]
            assert event["envelope"]["room"] == "room-a"

            posted_b1 = sender.post_message(envelope_for_room("room-b", "roomBfirst123")).json()
            event = ws_b.receive_json()
            assert event["envelope"]["id"] == posted_b1["id"]
            assert event["envelope"]["room"] == "room-b"

            # Un second message dans room-a : si le message de room-b
            # avait fuité dans la file de ws_a, c'est LUI qui sortirait
            # ici en premier (FIFO) et l'assertion suivante échouerait.
            posted_a2 = sender.post_message(envelope_for_room("room-a", "roomAsecond12")).json()
            event = ws_a.receive_json()
            assert event["envelope"]["id"] == posted_a2["id"]
            assert event["envelope"]["room"] == "room-a"


def test_list_rooms_never_exposes_password():
    with TestClient(main.app) as client:
        client.post("/rooms", json={"name": "listed-private", "password": "abc123"})
        rooms = client.get("/rooms").json()["rooms"]
        room_json_text = json.dumps(rooms)
        assert "abc123" not in room_json_text
        assert "password_hash" not in room_json_text
        # "has_password" (un booléen) est légitime et attendu ; seul le
        # secret et son hash ne doivent jamais apparaître.
        listed = next(r for r in rooms if r["name"] == "listed-private")
        assert listed["has_password"] is True
        assert set(listed.keys()) == {"name", "has_password", "message_count"}
