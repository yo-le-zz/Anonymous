"""
Serveur Anonymous — relais chiffré, sans identité applicative.

Le serveur :
- reçoit des enveloppes opaques (protocol_version, type, algorithm,
  key_id, nonce, ciphertext) qu'il ne peut pas déchiffrer ;
- les stocke, les diffuse par WebSocket, applique quotas/rétention ;
- ne connaît, ne stocke, ni ne journalise aucune identité applicative,
  clé privée, ou association message -> expéditeur.

Voir docs/architecture.md et docs/privacy.md pour le modèle de menace.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

import auth
import database
import session as session_module
import uvicorn
from config import Config
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from protocol import LoginRequest, SessionRequest, SignedEnvelopeIn, b64d
from ratelimit import ConnectionCounter, SlidingWindowLimiter
from retention import run_retention_loop
from storage import FileStorage, FileTooLarge, StorageQuotaExceeded

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("anonymous.server")

# ============================================================
# ÉTAT PARTAGÉ (aucune donnée par client persistée)
# ============================================================

database.configure(Config["storage"]["database"])
file_storage = FileStorage(
    Config["storage"]["files"],
    Config["files"]["max_file_size"],
    Config["storage"]["max_storage_bytes"],
)

message_limiter = SlidingWindowLimiter(
    max_events=Config["ratelimit"]["messages_per_minute"], window_seconds=60
)
upload_limiter = SlidingWindowLimiter(
    max_events=Config["ratelimit"]["uploads_per_minute"], window_seconds=60
)
session_limiter = SlidingWindowLimiter(
    max_events=Config["ratelimit"]["sessions_per_minute"], window_seconds=60
)
connection_counter = ConnectionCounter(Config["ratelimit"]["max_connections_per_ip"])

# Registre des sessions éphémères (identité de session Ed25519 + numéro
# "Anonymous #XXXXXX"). Vit UNIQUEMENT en RAM — voir session.py. Un
# redémarrage du serveur (donc de ce module) le vide entièrement.
session_registry = session_module.SessionRegistry(Config["session"]["ttl_seconds"])

_stop_event: asyncio.Event | None = None
_retention_task: asyncio.Task | None = None

# Connexions WebSocket actives. Cette liste est PUREMENT technique
# (pour la diffusion) : elle n'associe jamais une connexion à un
# message envoyé, et n'est jamais journalisée ni persistée.
_active_sockets: list[WebSocket] = []
_sockets_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _stop_event, _retention_task

    database.init_database()
    logger.info("database initialized")

    _stop_event = asyncio.Event()
    _retention_task = asyncio.create_task(
        run_retention_loop(Config, file_storage, session_registry=session_registry, stop_event=_stop_event)
    )

    logger.info("server started")

    yield

    _stop_event.set()
    if _retention_task:
        await _retention_task


app = FastAPI(title="Anonymous", version="2.0.0", lifespan=lifespan)


# ============================================================
# AUTHENTIFICATION
# ============================================================

def _client_ip(request: Request) -> str:
    # Utilisée UNIQUEMENT en mémoire pour le rate limiting (voir
    # ratelimit.py) : jamais journalisée, jamais stockée.
    if request.client is None:
        return "unknown"
    return request.client.host


def _require_auth(authorization_header: str | None) -> None:
    if not Config["auth"]["enabled"]:
        return

    token = auth.extract_bearer_token(authorization_header)

    if not auth.verify_token(token):
        raise HTTPException(status_code=401, detail="authentification requise ou jeton invalide.")


@app.post("/auth/login")
def login(data: LoginRequest, request: Request):
    if not Config["auth"]["enabled"]:
        raise HTTPException(status_code=400, detail="l'authentification n'est pas activée sur ce serveur.")

    ip = _client_ip(request)
    if not message_limiter.allow(f"login:{ip}"):
        raise HTTPException(status_code=429, detail="trop de tentatives, réessayez plus tard.")

    if not auth.verify_password(data.password, Config["auth"]["password_hash"]):
        raise HTTPException(status_code=401, detail="mot de passe incorrect.")

    token = auth.issue_token()
    return {"token": token, "expires_in": auth.TOKEN_TTL_SECONDS}


# ============================================================
# INFOS SERVEUR / SANTÉ
# ============================================================

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/server-info")
def server_info():
    return {
        "protocol_version": 1,
        "auth_required": Config["auth"]["enabled"],
        "max_message_size": Config["messages"]["max_size"],
        "max_file_size": Config["files"]["max_file_size"],
        "files_enabled": Config["files"]["enabled"],
        "key_rotation_messages": Config["crypto"]["key_rotation_messages"],
        "key_rotation_seconds": Config["crypto"]["key_rotation_seconds"],
        "session_ttl_seconds": Config["session"]["ttl_seconds"],
    }


# ============================================================
# SESSION ÉPHÉMÈRE (identité visuelle "Anonymous #XXXXXX")
# ============================================================

@app.post("/session")
def create_session(data: SessionRequest, request: Request):
    """Établit une session éphémère : le client fournit une clé
    publique Ed25519 fraîchement générée (jamais réutilisée d'une
    session à l'autre), le serveur lui attribue en retour un
    session_id aléatoire et un numéro pseudonyme "Anonymous #XXXXXX".

    Rien de ceci n'est stocké en base ni journalisé — voir session.py.
    """

    _require_auth(request.headers.get("authorization"))

    ip = _client_ip(request)
    if not session_limiter.allow(ip):
        raise HTTPException(status_code=429, detail="trop de sessions créées, ralentissez.")

    try:
        public_key_bytes = b64d(data.public_key)
    except Exception:
        raise HTTPException(status_code=422, detail="clé publique invalide (encodage).")

    try:
        session_id, number, ttl = session_registry.create_session(public_key_bytes)
    except session_module.InvalidPublicKey as error:
        raise HTTPException(status_code=422, detail=str(error))

    return {"session_id": session_id, "anonymous_number": number, "expires_in": ttl}


# ============================================================
# BROADCAST WEBSOCKET
# ============================================================

async def broadcast(data: dict) -> None:
    async with _sockets_lock:
        sockets = list(_active_sockets)

    dead = []
    for socket in sockets:
        try:
            await socket.send_json(data)
        except Exception:
            dead.append(socket)

    if dead:
        async with _sockets_lock:
            for socket in dead:
                if socket in _active_sockets:
                    _active_sockets.remove(socket)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    authorization = websocket.headers.get("authorization")

    if Config["auth"]["enabled"]:
        token = auth.extract_bearer_token(authorization)
        if not auth.verify_token(token):
            await websocket.close(code=4401)
            return

    ip = websocket.client.host if websocket.client else "unknown"

    if not connection_counter.try_acquire(ip):
        await websocket.close(code=4429)
        return

    await websocket.accept()

    async with _sockets_lock:
        _active_sockets.append(websocket)

    try:
        while True:
            # Le serveur n'a besoin de rien lire du client sur ce canal
            # (la création de message passe par POST /messages) ; on
            # attend juste les frames de contrôle / la déconnexion.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        async with _sockets_lock:
            if websocket in _active_sockets:
                _active_sockets.remove(websocket)
        connection_counter.release(ip)


# ============================================================
# ENVELOPPE PUBLIQUE (jamais de champ d'identité)
# ============================================================

def public_envelope(message: dict) -> dict:
    return {
        "id": message["id"],
        "protocol_version": message["protocol_version"],
        "type": message["envelope_type"],
        "algorithm": message["algorithm"],
        "key_id": message["key_id"],
        "nonce": message["nonce"],
        "ciphertext": message["ciphertext"],
        "created_at": message["created_at"],
        "anonymous_number": message["anonymous_number"],
    }


# ============================================================
# MESSAGES
# ============================================================

@app.post("/messages")
async def create_new_message(envelope: SignedEnvelopeIn, request: Request):
    _require_auth(request.headers.get("authorization"))

    ip = _client_ip(request)
    if not message_limiter.allow(ip):
        raise HTTPException(status_code=429, detail="trop de messages, ralentissez.")

    try:
        envelope.validate_semantics(Config["messages"]["max_size"])
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    session_info = session_registry.get(envelope.session_id)
    if session_info is None:
        raise HTTPException(
            status_code=401,
            detail="session inconnue ou expirée : établissez une nouvelle session via /session.",
        )

    try:
        signature_bytes = b64d(envelope.signature)
    except Exception:
        raise HTTPException(status_code=422, detail="signature invalide (encodage).")

    if not session_registry.verify_signature(
        envelope.session_id, envelope.canonical_bytes(), signature_bytes
    ):
        # Signature invalide : soit corruption, soit tentative
        # d'usurpation d'un session_id qui ne nous appartient pas.
        # Dans les deux cas, le message est refusé sans distinction
        # (ne pas donner d'indice permettant d'affiner une attaque).
        raise HTTPException(status_code=401, detail="signature invalide : message refusé.")

    message = database.create_message(
        envelope_type=envelope.type,
        protocol_version=envelope.protocol_version,
        algorithm=envelope.algorithm,
        key_id=envelope.key_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        anonymous_number=session_info.anonymous_number,
    )

    public = public_envelope(message)

    await broadcast({"type": "message_created", "envelope": public})

    return public


@app.get("/messages")
def history(request: Request, limit: int = 50):
    _require_auth(request.headers.get("authorization"))
    limit = max(1, min(limit, 200))
    return {"messages": [public_envelope(m) for m in database.get_messages(limit)]}


@app.get("/messages/{message_id}")
def get_one_message(message_id: int, request: Request):
    _require_auth(request.headers.get("authorization"))

    message = database.get_message(message_id)

    if message is None:
        raise HTTPException(status_code=404, detail="message introuvable.")

    return public_envelope(message)


# ============================================================
# FICHIERS
# ============================================================

async def _iter_request_body(request: Request):
    async for chunk in request.stream():
        if chunk:
            yield chunk


@app.post("/files")
async def upload_file(request: Request):
    _require_auth(request.headers.get("authorization"))

    if not Config["files"]["enabled"]:
        raise HTTPException(status_code=403, detail="les fichiers sont désactivés sur ce serveur.")

    ip = _client_ip(request)
    if not upload_limiter.allow(ip):
        raise HTTPException(status_code=429, detail="trop d'envois de fichiers, ralentissez.")

    current_usage = database.total_storage_bytes()

    try:
        file_id, size = await file_storage.save_stream(
            _iter_request_body(request), current_usage
        )
    except FileTooLarge as error:
        raise HTTPException(status_code=413, detail=str(error))
    except StorageQuotaExceeded as error:
        raise HTTPException(status_code=507, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    database.register_file(file_id, size)

    return {"file_id": file_id, "size_bytes": size}


@app.get("/files/{file_id}")
def download_file(file_id: str, request: Request):
    _require_auth(request.headers.get("authorization"))

    record = database.get_file_record(file_id)
    if record is None:
        raise HTTPException(status_code=404, detail="fichier introuvable.")

    try:
        handle = file_storage.open_for_read(file_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(status_code=404, detail="fichier introuvable.")

    def iterator():
        try:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            handle.close()

    return StreamingResponse(iterator(), media_type="application/octet-stream")


# ============================================================
# DÉMARRAGE
# ============================================================

def main():
    import getpass
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "hash-password":
        password = getpass.getpass("Mot de passe du serveur : ")
        confirm = getpass.getpass("Confirmez : ")

        if password != confirm:
            print("Les mots de passe ne correspondent pas.")
            sys.exit(1)

        print()
        print("Ajoutez ceci à server.toml :")
        print()
        print("[auth]")
        print("enabled = true")
        print(f'password_hash = "{auth.hash_password(password)}"')
        return

    access_log = Config["logging"]["access_logs"]

    uvicorn.run(
        "main:app",
        host=Config["server"]["host"],
        port=Config["server"]["port"],
        access_log=access_log,
        log_level="info",
    )


if __name__ == "__main__":
    main()
