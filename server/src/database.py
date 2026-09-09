"""
Accès SQLite du serveur.

Schéma volontairement minimal — voir docs/privacy.md pour la
justification de chaque colonne. Aucune des colonnes suivantes
n'existe et ne doit JAMAIS être ajoutée :

    owner, client_token, user_id, client_id, ip, username, session_id, public_key

Une ligne de la table `messages` est une enveloppe chiffrée opaque :
le serveur ne peut ni la lire, ni l'attribuer à une identité réelle.

Table `rooms` : canaux publics côté serveur (nom + éventuel hash de
mot de passe Argon2id). Ce n'est pas une identité utilisateur — voir
la section dédiée plus bas dans ce fichier et `docs/crypto.md`.

Exception documentée : `anonymous_number`. C'est le numéro pseudonyme
"Anonymous #XXXXXX" attribué ALÉATOIREMENT par le serveur à une
session éphémère (voir session.py), affiché tel quel côté client. Ce
n'est PAS un identifiant permanent : une nouvelle session obtient
toujours un nouveau numéro tiré au hasard, et rien dans ce schéma ne
relie un numéro à une clé publique, une IP, ou une autre session
passée ou future. Le stocker ici permet uniquement à l'historique
d'afficher les mêmes numéros que ceux vus en direct pendant cette
session (cohérence d'affichage) ; cela ne crée aucune corrélation qui
n'existait pas déjà de façon visible pendant la session elle-même.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

_local = threading.local()

_db_path: Path | None = None
_write_lock = threading.Lock()


def configure(database_path: str) -> None:
    global _db_path
    _db_path = Path(database_path)
    _db_path.parent.mkdir(parents=True, exist_ok=True)


def _connection() -> sqlite3.Connection:
    if not hasattr(_local, "connection"):
        if _db_path is None:
            raise RuntimeError("database.configure() doit être appelé avant toute requête.")

        connection = sqlite3.connect(_db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        _local.connection = connection

    return _local.connection


@contextmanager
def transaction():
    connection = _connection()
    with _write_lock:
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def _existing_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def init_database() -> None:
    """Crée le schéma s'il n'existe pas, PUIS applique les migrations
    incrémentales nécessaires sur une base déjà existante créée par une
    version antérieure du serveur.

    `CREATE TABLE IF NOT EXISTS` ne modifie jamais une table déjà
    présente : sur une base créée avant l'introduction d'une colonne
    (ex. `room`, `anonymous_number`), il faut l'ajouter explicitement
    via `ALTER TABLE ... ADD COLUMN`, sans quoi le serveur refuse de
    démarrer (`sqlite3.OperationalError: no such column`)."""

    with transaction() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                envelope_type TEXT NOT NULL,
                protocol_version INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

        # Un salon est un canal PUBLIC (nom + éventuel mot de passe de
        # salon). Ce n'est PAS le secret de chiffrement de bout en bout
        # (celui-ci reste exclusivement côté client, voir docs/crypto.md) :
        # c'est un simple espace de nommage/contrôle d'accès côté
        # serveur, jamais associé à un expéditeur. Le mot de passe n'est
        # jamais stocké en clair (Argon2id, comme le mot de passe
        # serveur global — voir auth.py).
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS rooms (
                name TEXT PRIMARY KEY,
                password_hash TEXT,
                created_at REAL NOT NULL
            )
            """
        )

        # ---- Migrations incrémentales (bases pré-existantes) ----

        messages_columns = _existing_columns(connection, "messages")

        if "anonymous_number" not in messages_columns:
            # Introduit avec les sessions éphémères signées (v1.0.0).
            # Les lignes déjà en base n'ont, par définition, jamais été
            # rattachées à une session : 0 est une valeur sentinelle
            # neutre, jamais une valeur qu'une vraie session n'obtient
            # (les numéros réels vont de 100000 à 999999 — voir
            # session.py), donc sans ambiguïté ni fausse identité.
            connection.execute(
                "ALTER TABLE messages ADD COLUMN anonymous_number INTEGER NOT NULL DEFAULT 0"
            )

        if "room" not in messages_columns:
            # Introduit avec les salons (v1.0.1). Les messages déjà en
            # base retombent dans le salon par défaut.
            connection.execute(
                "ALTER TABLE messages ADD COLUMN room TEXT NOT NULL DEFAULT 'general'"
            )

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages (created_at)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_room ON messages (room)"
        )


# ============================================================
# MESSAGES
# ============================================================

def create_message(
    envelope_type: str,
    protocol_version: int,
    algorithm: str,
    key_id: str,
    nonce: str,
    ciphertext: str,
    anonymous_number: int,
    room: str = "general",
) -> dict:
    import time

    size_bytes = len(ciphertext)

    with transaction() as connection:
        cursor = connection.execute(
            """
            INSERT INTO messages (
                envelope_type, protocol_version, algorithm,
                key_id, nonce, ciphertext, size_bytes, created_at,
                anonymous_number, room
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                envelope_type,
                protocol_version,
                algorithm,
                key_id,
                nonce,
                ciphertext,
                size_bytes,
                time.time(),
                anonymous_number,
                room,
            ),
        )
        message_id = cursor.lastrowid

    return get_message(message_id)


def get_message(message_id: int) -> dict | None:
    connection = _connection()
    row = connection.execute(
        "SELECT * FROM messages WHERE id = ?", (message_id,)
    ).fetchone()
    return dict(row) if row else None


def get_messages(limit: int = 50, room: str | None = None) -> list[dict]:
    connection = _connection()

    if room is not None:
        rows = connection.execute(
            "SELECT * FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?",
            (room, limit),
        ).fetchall()
    else:
        rows = connection.execute(
            "SELECT * FROM messages ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    return [dict(row) for row in reversed(rows)]


def count_messages(room: str | None = None) -> int:
    connection = _connection()

    if room is not None:
        return connection.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE room = ?", (room,)
        ).fetchone()["n"]

    return connection.execute("SELECT COUNT(*) AS n FROM messages").fetchone()["n"]


def count_messages_since(cutoff_timestamp: float) -> int:
    connection = _connection()
    return connection.execute(
        "SELECT COUNT(*) AS n FROM messages WHERE created_at >= ?", (cutoff_timestamp,)
    ).fetchone()["n"]


def delete_messages_older_than(cutoff_timestamp: float) -> int:
    with transaction() as connection:
        cursor = connection.execute(
            "DELETE FROM messages WHERE created_at < ?", (cutoff_timestamp,)
        )
        return cursor.rowcount


def delete_oldest_messages(count: int) -> int:
    if count <= 0:
        return 0

    with transaction() as connection:
        cursor = connection.execute(
            """
            DELETE FROM messages
            WHERE id IN (
                SELECT id FROM messages ORDER BY id ASC LIMIT ?
            )
            """,
            (count,),
        )
        return cursor.rowcount


# ============================================================
# FICHIERS
# ============================================================

def register_file(file_id: str, size_bytes: int) -> None:
    import time

    with transaction() as connection:
        connection.execute(
            "INSERT INTO files (file_id, size_bytes, created_at) VALUES (?, ?, ?)",
            (file_id, size_bytes, time.time()),
        )


def get_file_record(file_id: str) -> dict | None:
    connection = _connection()
    row = connection.execute(
        "SELECT * FROM files WHERE file_id = ?", (file_id,)
    ).fetchone()
    return dict(row) if row else None


def delete_file_record(file_id: str) -> None:
    with transaction() as connection:
        connection.execute("DELETE FROM files WHERE file_id = ?", (file_id,))


def list_files_older_than(cutoff_timestamp: float) -> list[str]:
    connection = _connection()
    rows = connection.execute(
        "SELECT file_id FROM files WHERE created_at < ?", (cutoff_timestamp,)
    ).fetchall()
    return [row["file_id"] for row in rows]


def total_storage_bytes() -> int:
    connection = _connection()
    messages_total = connection.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM messages"
    ).fetchone()["total"]
    files_total = connection.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS total FROM files"
    ).fetchone()["total"]
    return int(messages_total) + int(files_total)


# ============================================================
# SALONS (rooms) — canaux publics côté serveur, PAS une identité
# ============================================================
#
# Un salon partitionne les messages par canal (comme des salons IRC),
# rien de plus. Il n'existe aucune colonne reliant un salon à un
# expéditeur : `rooms` ne contient que le nom, un éventuel hash de mot
# de passe (Argon2id, jamais le mot de passe en clair), et la date de
# création. Voir docs/crypto.md pour la distinction avec le secret de
# chiffrement de bout en bout (qui reste toujours uniquement côté
# client).

def create_room(name: str, password_hash: str | None) -> dict | None:
    import time

    try:
        with transaction() as connection:
            connection.execute(
                "INSERT INTO rooms (name, password_hash, created_at) VALUES (?, ?, ?)",
                (name, password_hash, time.time()),
            )
    except sqlite3.IntegrityError:
        return None  # existe déjà

    return get_room(name)


def get_room(name: str) -> dict | None:
    connection = _connection()
    row = connection.execute("SELECT * FROM rooms WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def list_rooms() -> list[dict]:
    """Liste agrégée : nom, si un mot de passe est requis (jamais le
    mot de passe/hash lui-même), et nombre de messages — jamais
    d'information par utilisateur."""

    connection = _connection()
    rows = connection.execute(
        """
        SELECT
            rooms.name AS name,
            (rooms.password_hash IS NOT NULL AND rooms.password_hash != '') AS has_password,
            rooms.created_at AS created_at,
            COUNT(messages.id) AS message_count
        FROM rooms
        LEFT JOIN messages ON messages.room = rooms.name
        GROUP BY rooms.name
        ORDER BY rooms.name ASC
        """
    ).fetchall()

    return [
        {
            "name": row["name"],
            "has_password": bool(row["has_password"]),
            "message_count": row["message_count"],
        }
        for row in rows
    ]


def count_rooms() -> int:
    connection = _connection()
    return connection.execute("SELECT COUNT(*) AS n FROM rooms").fetchone()["n"]
