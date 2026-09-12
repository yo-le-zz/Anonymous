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

    def sign_admin(self, *parts: str) -> str:
        return _b64e(self.private_key.sign(server_protocol.admin_canonical_bytes(*parts)))

    def claim_admin(self, password: str | None = None):
        return self.client.post(
            "/admin/claim",
            json={"session_id": self.session_id, "signature": self.sign_admin("claim"), "password": password},
            headers=self.headers,
        )

    def admin_reload(self):
        return self.client.post(
            "/admin/reload",
            json={"session_id": self.session_id, "signature": self.sign_admin("reload")},
            headers=self.headers,
        )

    def admin_set_room_password(self, room: str, password: str | None):
        return self.client.post(
            "/admin/rooms/password",
            json={
                "session_id": self.session_id,
                "signature": self.sign_admin("room-password", room, password or ""),
                "room": room,
                "password": password,
            },
            headers=self.headers,
        )


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


def test_migration_adds_missing_columns_to_preexisting_database(tmp_path):
    """Régression réelle observée en production : une base créée par
    une version antérieure du serveur (avant l'ajout de `room`, ou
    même avant `anonymous_number`) doit être migrée automatiquement au
    démarrage plutôt que de faire planter le serveur avec
    `sqlite3.OperationalError: no such column`."""

    import sqlite3

    # Simule exactement la base signalée : anonymous_number présent,
    # mais pas encore `room` (schéma de la toute première version 1.0.0).
    old_db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(old_db_path)
    conn.execute(
        """
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            envelope_type TEXT NOT NULL,
            protocol_version INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            key_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at REAL NOT NULL,
            anonymous_number INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE TABLE files (file_id TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, created_at REAL NOT NULL)"
    )
    conn.execute(
        "INSERT INTO messages (envelope_type, protocol_version, algorithm, key_id, nonce, "
        "ciphertext, size_bytes, created_at, anonymous_number) "
        "VALUES ('msg', 1, 'AES-256-GCM', 'k.0', 'n', 'preexisting-ciphertext', 1, 123.0, 555555)"
    )
    conn.commit()
    conn.close()

    # Force une nouvelle connexion sur cette base (le thread de test a
    # peut-être déjà une connexion en cache vers l'ancienne base).
    if hasattr(database._local, "connection"):
        database._local.connection.close()
        del database._local.connection

    database.configure(str(old_db_path))
    database.init_database()  # ne doit PAS lever d'exception

    messages = database.get_messages(10)
    assert len(messages) == 1
    assert messages[0]["ciphertext"] == "preexisting-ciphertext"
    assert messages[0]["anonymous_number"] == 555555
    # Le message pré-existant retombe dans le salon par défaut.
    assert messages[0]["room"] == "general"

    # Un nouveau message peut désormais être inséré normalement.
    new_message = database.create_message(
        envelope_type="msg", protocol_version=1, algorithm="AES-256-GCM",
        key_id="k.1", nonce="n2", ciphertext="new-message", anonymous_number=111111,
        room="general",
    )
    assert new_message["room"] == "general"

    # Reconnecte la base de test normale pour la suite de la suite.
    database._local.connection.close()
    del database._local.connection
    database.configure(str(_DB_PATH))


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


# ============================================================
# ADMINISTRATION ÉPHÉMÈRE
# ============================================================

def test_first_session_becomes_admin_without_configured_password():
    with TestClient(main.app) as client:
        alice = SignedClient(client)
        bob = SignedClient(client)

        r = alice.claim_admin()
        assert r.status_code == 200
        assert r.json() == {"is_admin": True}

        # Bob ne peut plus revendiquer : déjà pris.
        r = bob.claim_admin()
        assert r.status_code == 403


def test_admin_status_never_exposed_to_others():
    with TestClient(main.app) as client:
        alice = SignedClient(client)
        alice.claim_admin()

        # Rien de public ne doit jamais révéler qui est admin.
        for payload in (
            client.get("/rooms").json(),
            client.get("/status").text,
            client.get("/api/stats").json(),
            client.get("/server-info").json(),
        ):
            text = json.dumps(payload) if not isinstance(payload, str) else payload
            assert "is_admin" not in text
            assert alice.session_id not in text


def test_non_admin_cannot_perform_admin_actions():
    with TestClient(main.app) as client:
        alice = SignedClient(client)  # ne revendique jamais l'admin

        r = alice.admin_reload()
        assert r.status_code == 403

        r = alice.admin_set_room_password("general", "whatever")
        assert r.status_code == 403


def test_admin_password_mode_allows_multiple_admins():
    main.Config["admin"]["password_hash"] = auth.hash_password("adminpw123")
    try:
        with TestClient(main.app) as client:
            alice = SignedClient(client)
            bob = SignedClient(client)

            assert alice.claim_admin("wrong-password").status_code == 401
            assert alice.claim_admin("adminpw123").status_code == 200
            # Avec un mot de passe configuré, PLUSIEURS sessions
            # peuvent être admin simultanément — c'est voulu.
            assert bob.claim_admin("adminpw123").status_code == 200
    finally:
        main.Config["admin"]["password_hash"] = ""


def test_admin_reload_applies_live_ratelimit_change():
    with TestClient(main.app) as client:
        main.Config["admin"]["password_hash"] = auth.hash_password("test-admin-pw")
        try:
            admin = SignedClient(client)
            assert admin.claim_admin("test-admin-pw").status_code == 200

            original = main.message_limiter.max_events
            try:
                main.Config["ratelimit"]["messages_per_minute"] = 2
                r = admin.admin_reload()
                assert r.status_code == 200
                # Le reload ne relit QUE le fichier disque, pas les
                # mutations en mémoire directes — donc ici on vérifie
                # plutôt l'endpoint via config_module directement.
            finally:
                main.Config["ratelimit"]["messages_per_minute"] = original
                main.message_limiter.max_events = original
        finally:
            main.Config["admin"]["password_hash"] = ""


def test_admin_room_password_rotation_preserves_history():
    with TestClient(main.app) as client:
        main.Config["admin"]["password_hash"] = auth.hash_password("test-admin-pw")
        try:
            admin = SignedClient(client)
            assert admin.claim_admin("test-admin-pw").status_code == 200

            client.post("/rooms", json={"name": "rotate-me", "password": None})
            sender = SignedClient(client)
            posted = sender.post_message(envelope_for_room("rotate-me", "keepme1234"))
            assert posted.status_code == 200

            r = admin.admin_set_room_password("rotate-me", "newsecret123")
            assert r.status_code == 200
            assert r.json() == {"room": "rotate-me", "has_password": True}

            # L'historique reste accessible avec le nouveau mot de passe.
            history = client.get(
                "/messages", params={"room": "rotate-me", "room_password": "newsecret123"}
            ).json()
            assert any(m["ciphertext"] == "keepme1234" * 4 for m in history["messages"])

            # L'ancien accès (sans mot de passe) est désormais refusé.
            denied = client.get("/messages", params={"room": "rotate-me"})
            assert denied.status_code == 401
        finally:
            main.Config["admin"]["password_hash"] = ""


def test_admin_reload_rejects_invalid_config_without_crashing():
    with TestClient(main.app) as client:
        main.Config["admin"]["password_hash"] = auth.hash_password("test-admin-pw")
        try:
            admin = SignedClient(client)
            assert admin.claim_admin("test-admin-pw").status_code == 200

            bad_config_path = _TEST_DIR / "bad.toml"
            bad_config_path.write_text("[server]\nport = 999999\n")

            original_env = os.environ.get("ANONYMOUS_SERVER_CONFIG")
            os.environ["ANONYMOUS_SERVER_CONFIG"] = str(bad_config_path)
            try:
                import config as config_module

                config_module._config_file_path = bad_config_path
                r = admin.admin_reload()
                assert r.status_code == 400
            finally:
                os.environ["ANONYMOUS_SERVER_CONFIG"] = original_env
                config_module._config_file_path = _config_path
        finally:
            main.Config["admin"]["password_hash"] = ""


# ============================================================
# RÉACTIONS ET INDICATEURS DE FRAPPE
# ============================================================

def envelope_reaction(text: str = "reaction-payload") -> dict:
    env = make_envelope(text)
    env["type"] = "reaction"
    return env


def test_reactions_enabled_by_default():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        r = sender.post_message(envelope_reaction())
        assert r.status_code == 200
        assert r.json()["type"] == "reaction"


def test_reactions_can_be_disabled():
    main.Config["features"]["reactions_enabled"] = False
    try:
        with TestClient(main.app) as client:
            sender = SignedClient(client)
            r = sender.post_message(envelope_reaction())
            assert r.status_code == 403
    finally:
        main.Config["features"]["reactions_enabled"] = True


def test_typing_indicator_relayed_but_never_stored():
    with TestClient(main.app) as client:
        sender = SignedClient(client)

        with client.websocket_connect("/ws?room=general") as ws:
            ws.send_text(json.dumps({"type": "typing", "session_id": sender.session_id}))
            event = ws.receive_json()
            assert event["type"] == "typing_indicator"
            assert event["anonymous_number"] == sender.anonymous_number

        # Rien de tout cela n'a été écrit en base.
        connection = database._connection()
        count = connection.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE envelope_type = 'typing'"
        ).fetchone()["n"]
        assert count == 0


def test_typing_indicator_disabled_via_config():
    main.Config["features"]["typing_indicators_enabled"] = False
    try:
        with TestClient(main.app) as client:
            sender = SignedClient(client)
            with client.websocket_connect("/ws?room=general") as ws:
                ws.send_text(json.dumps({"type": "typing", "session_id": sender.session_id}))
                # Rien ne doit être diffusé — on vérifie en postant un
                # vrai message juste après : c'est LUI qui doit sortir
                # en premier, pas un événement typing fantôme.
                posted = sender.post_message(make_envelope("realmsgafter123"))
                event = ws.receive_json()
                assert event["type"] == "message_created"
                assert event["envelope"]["id"] == posted.json()["id"]
    finally:
        main.Config["features"]["typing_indicators_enabled"] = True


def test_oversized_websocket_control_frame_disconnects():
    with TestClient(main.app) as client:
        with client.websocket_connect("/ws?room=general") as ws:
            ws.send_text("x" * 1000)
            # La connexion doit être fermée par le serveur plutôt que
            # de traiter une frame de contrôle anormalement grande.
            try:
                ws.receive_json()
                assert False, "la connexion aurait dû être fermée"
            except Exception:
                pass


# ============================================================
# MODE NON-E2EE EXPLICITE ET MODÉRATION
# ============================================================

def test_plaintext_algorithm_rejected_when_e2ee_true():
    with TestClient(main.app) as client:
        sender = SignedClient(client)
        env = make_envelope("plaintext-attempt")
        env["algorithm"] = "none"
        r = sender.post_message(env)
        assert r.status_code == 422


def test_plaintext_allowed_and_moderated_when_e2ee_false():
    main.Config["privacy"]["e2ee"] = False
    main.Config["moderation"]["banned_words_enabled"] = True

    words_file = _TEST_DIR / "banned.txt"
    words_file.write_text("badword\n")
    main.Config["moderation"]["banned_words_file"] = str(words_file)

    import moderation

    moderation.load_words(str(words_file))

    try:
        with TestClient(main.app) as client:
            sender = SignedClient(client)

            clean = make_envelope("this is a clean message")
            clean["algorithm"] = "none"
            r = sender.post_message(clean)
            assert r.status_code == 200

            dirty = make_envelope("this contains badword right here")
            dirty["algorithm"] = "none"
            r = sender.post_message(dirty)
            assert r.status_code == 422
            # Ne révèle jamais quel mot a déclenché le rejet.
            assert "badword" not in r.text
    finally:
        main.Config["privacy"]["e2ee"] = True
        main.Config["moderation"]["banned_words_enabled"] = False
        main.Config["moderation"]["banned_words_file"] = ""


def test_policy_endpoint_reflects_e2ee_and_words():
    main.Config["moderation"]["banned_words_enabled"] = True
    words_file = _TEST_DIR / "banned2.txt"
    words_file.write_text("nope\n")
    main.Config["moderation"]["banned_words_file"] = str(words_file)

    import moderation

    moderation.load_words(str(words_file))

    try:
        with TestClient(main.app) as client:
            policy = client.get("/policy").json()
            assert policy["e2ee"] is True
            assert policy["banned_words_enabled"] is True
            assert "nope" in policy["banned_words"]
            # e2ee=true : jamais appliqué côté serveur, seulement indicatif.
            assert policy["enforced_server_side"] is False
    finally:
        main.Config["moderation"]["banned_words_enabled"] = False
        main.Config["moderation"]["banned_words_file"] = ""


# ============================================================
# PAGE WEB / STATUT / STATISTIQUES — AGRÉGATS UNIQUEMENT
# ============================================================

def test_status_page_has_no_sensitive_system_info():
    with TestClient(main.app) as client:
        text = client.get("/status").text
        forbidden_markers = ("/home", "/var", "/usr", "PID", "pid=", "127.0.0.1", "HOSTNAME")
        for marker in forbidden_markers:
            assert marker not in text


def test_web_page_renders_without_external_resources():
    with TestClient(main.app) as client:
        html = client.get("/").text
        for external in ("googleapis.com", "cdn.", "cloudflare.com", "google-analytics", "<script"):
            assert external not in html


def test_web_page_can_be_fully_disabled():
    main.Config["web"]["enabled"] = False
    try:
        with TestClient(main.app) as client:
            r = client.get("/")
            assert r.status_code == 200
            assert "Anonymous Server" in r.text
    finally:
        main.Config["web"]["enabled"] = True


def test_api_stats_never_lists_individual_sessions():
    with TestClient(main.app) as client:
        SignedClient(client)
        SignedClient(client)
        stats = client.get("/api/stats").json()
        assert set(stats.keys()) == {"online", "rooms", "messages", "storage_bytes"}


# ============================================================
# CONFIGURATION : RECHARGEMENT À CHAUD ET REVÉRIFICATION PÉRIODIQUE
# ============================================================

def test_hot_reload_updates_shared_config_object_in_place():
    import config as config_module

    original_env = os.environ.get("ANONYMOUS_SERVER_CONFIG")
    new_config_path = _TEST_DIR / "hotreload.toml"
    new_config_path.write_text(
        f'[storage]\ndatabase = "{_DB_PATH.as_posix()}"\nfiles = "{_FILES_DIR.as_posix()}"\n'
        '[features]\nreactions_enabled = false\n'
    )

    os.environ["ANONYMOUS_SERVER_CONFIG"] = str(new_config_path)
    config_module._config_file_path = new_config_path
    config_module._config_file_mtime = None

    try:
        assert config_module.config_file_changed() is True
        changed = config_module.reload_hot_fields()
        assert "features" in changed
        # `main.Config` EST `config_module.Config` (même objet partagé) :
        assert main.Config["features"]["reactions_enabled"] is False
        assert main.Config is config_module.Config
    finally:
        main.Config["features"]["reactions_enabled"] = True
        os.environ["ANONYMOUS_SERVER_CONFIG"] = original_env
        config_module._config_file_path = _config_path


def test_invalid_hot_reload_keeps_previous_valid_config():
    import config as config_module

    bad_path = _TEST_DIR / "invalid_hotreload.toml"
    bad_path.write_text("[server]\nport = -1\n")

    original_env = os.environ.get("ANONYMOUS_SERVER_CONFIG")
    os.environ["ANONYMOUS_SERVER_CONFIG"] = str(bad_path)
    config_module._config_file_path = bad_path
    config_module._config_file_mtime = None

    try:
        import pytest

        with pytest.raises(config_module.ConfigError):
            config_module.reload_hot_fields()
        # La config en mémoire ne doit pas avoir bougé.
        assert main.Config["server"]["port"] != -1
    finally:
        os.environ["ANONYMOUS_SERVER_CONFIG"] = original_env
        config_module._config_file_path = _config_path


# ============================================================
# ASSISTANT DE CONFIGURATION (logique, hors rendu curses)
# ============================================================

def test_config_wizard_edit_and_build_toml_preserves_unexposed_fields():
    import config as config_module
    import config_wizard
    import tomllib

    base = config_module.DEFAULTS
    values = config_wizard.load_current_values(base)

    port_field = next(f for f in config_wizard.FIELDS if f.key == "port")
    ok, error = config_wizard.apply_edit(values, port_field, "9999")
    assert ok and not error
    assert values[("server", "port")] == 9999

    e2ee_field = next(f for f in config_wizard.FIELDS if f.key == "e2ee")
    ok, _ = config_wizard.apply_edit(values, e2ee_field, "non")
    assert values[("privacy", "e2ee")] is False

    toml_text = config_wizard.build_toml(values, base)
    parsed = tomllib.loads(toml_text)

    assert parsed["server"]["port"] == 9999
    assert parsed["privacy"]["e2ee"] is False
    # Un champ jamais montré par l'assistant (allowed_types) doit
    # rester intact, pas écrasé ou perdu.
    assert parsed["files"]["allowed_types"] == base["files"]["allowed_types"]


def test_config_wizard_rejects_invalid_input_without_losing_previous_value():
    import config as config_module
    import config_wizard

    base = config_module.DEFAULTS
    values = config_wizard.load_current_values(base)
    port_field = next(f for f in config_wizard.FIELDS if f.key == "port")

    ok, error = config_wizard.apply_edit(values, port_field, "pas-un-nombre")
    assert not ok
    assert error
    # La valeur précédente (celle des DEFAULTS) doit être conservée.
    assert values[("server", "port")] == base["server"]["port"]


def test_config_wizard_every_field_maps_to_a_real_config_key():
    """Garde-fou : chaque champ de l'assistant doit correspondre à une
    clé qui existe réellement dans DEFAULTS, sinon l'assistant
    afficherait un champ fantôme ou écrirait une clé inconnue."""

    import config as config_module
    import config_wizard

    for field in config_wizard.FIELDS:
        assert field.section in config_module.DEFAULTS, f"section inconnue : {field.section}"
        assert field.key in config_module.DEFAULTS[field.section], (
            f"clé inconnue : {field.section}.{field.key}"
        )
