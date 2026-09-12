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

_SERVER_VERSION = "1.0.4"

# ============================================================
# BOOTSTRAP CLI — AVANT tout import lourd (FastAPI, cryptography...)
# ============================================================
#
# `--version` et `--config` sont traités ICI, avant même d'importer le
# reste de l'application : `anonymous-server --version` doit répondre
# instantanément et fonctionner même si server.toml est absent ou
# invalide. `--config PATH` doit être pris en compte AVANT que
# `config.py` ne charge son fichier par défaut (voir plus bas) — d'où
# la nécessité de le traiter avant les imports normaux.
#
# Les autres sous-commandes (hash-password, stats, cleanup, config,
# check-config...) sont gérées plus bas dans `main()`, après les
# imports : elles ont de toute façon besoin de la configuration ou de
# la base de données pour faire quoi que ce soit d'utile.

import os
import sys

if "--version" in sys.argv or "-V" in sys.argv:
    print(f"anonymous-server {_SERVER_VERSION}")
    sys.exit(0)

if "--config" in sys.argv:
    _idx = sys.argv.index("--config")
    if _idx + 1 >= len(sys.argv):
        print("Erreur : --config nécessite un chemin.", file=sys.stderr)
        sys.exit(2)
    os.environ["ANONYMOUS_SERVER_CONFIG"] = sys.argv[_idx + 1]
    del sys.argv[_idx : _idx + 2]
elif any(arg.startswith("--config=") for arg in sys.argv):
    _idx = next(i for i, arg in enumerate(sys.argv) if arg.startswith("--config="))
    os.environ["ANONYMOUS_SERVER_CONFIG"] = sys.argv[_idx].split("=", 1)[1]
    del sys.argv[_idx]

# ============================================================
# IMPORTS (après prise en compte de --config ci-dessus)
# ============================================================

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager

import auth
import config as config_module
import database
import moderation
import session as session_module
import uvicorn
from config import Config
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from protocol import (
    AdminClaimRequest,
    AdminReloadRequest,
    AdminRoomPasswordRequest,
    LoginRequest,
    RoomCreateRequest,
    SessionRequest,
    SignedEnvelopeIn,
    b64d,
    is_valid_room_name,
)
from ratelimit import ConnectionCounter, ProgressiveCooldown, SlidingWindowLimiter
from retention import run_retention_loop, run_retention_once
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

# Cooldown progressif (voir docs/server.md "Anti-spam") : un par
# catégorie de limite, pour qu'un abus de messages n'affecte pas le
# cooldown des uploads ou des créations de session.
message_cooldown = ProgressiveCooldown(Config["ratelimit"]["progressive_cooldown_max_seconds"])
upload_cooldown = ProgressiveCooldown(Config["ratelimit"]["progressive_cooldown_max_seconds"])
session_cooldown = ProgressiveCooldown(Config["ratelimit"]["progressive_cooldown_max_seconds"])
_all_cooldowns = [message_cooldown, upload_cooldown, session_cooldown]

if Config["moderation"]["banned_words_enabled"]:
    moderation.load_words(Config["moderation"]["banned_words_file"])

# Registre des sessions éphémères (identité de session Ed25519 + numéro
# "Anonymous #XXXXXX"). Vit UNIQUEMENT en RAM — voir session.py. Un
# redémarrage du serveur (donc de ce module) le vide entièrement.
session_registry = session_module.SessionRegistry(Config["session"]["ttl_seconds"])

_server_started_at = time.time()
_stop_event: asyncio.Event | None = None
_retention_task: asyncio.Task | None = None

# Connexions WebSocket actives, associées au SALON qu'elles écoutent
# (pour ne diffuser un message qu'aux connexions du bon salon). Cette
# table est PUREMENT technique (routage de diffusion) : elle n'est
# jamais journalisée, jamais persistée, et ne relie jamais une
# connexion à un message stocké — voir docs/privacy.md.
_active_sockets: dict[WebSocket, str] = {}
_sockets_lock = asyncio.Lock()


def _apply_ratelimit_config(_changed_sections=None) -> None:
    """Resynchronise les objets de limitation de débit déjà construits
    (leurs attributs sont mutables, mais pas relus dynamiquement depuis
    `Config` à chaque requête pour des raisons de performance) avec la
    configuration actuelle. Appelée après tout rechargement à chaud —
    `/admin/reload` et la revérification périodique automatique (voir
    retention.py) — sans quoi changer `[ratelimit]` dans server.toml
    n'aurait aucun effet tant que le processus n'est pas redémarré."""

    message_limiter.max_events = Config["ratelimit"]["messages_per_minute"]
    upload_limiter.max_events = Config["ratelimit"]["uploads_per_minute"]
    session_limiter.max_events = Config["ratelimit"]["sessions_per_minute"]
    connection_counter.max_per_ip = Config["ratelimit"]["max_connections_per_ip"]

    new_max_cooldown = Config["ratelimit"]["progressive_cooldown_max_seconds"]
    for cooldown in _all_cooldowns:
        cooldown.max_seconds = new_max_cooldown

    session_registry.ttl_seconds = Config["session"]["ttl_seconds"]


def _check_rate_limit(
    limiter: SlidingWindowLimiter, cooldown: ProgressiveCooldown, key: str, message: str
) -> None:
    """Applique la limite de débit, avec cooldown progressif si activé
    en configuration (voir `[ratelimit] progressive_cooldown_enabled` —
    TOUJOURS annoncé publiquement via /server-info, comme demandé)."""

    progressive = Config["ratelimit"]["progressive_cooldown_enabled"]

    if progressive:
        remaining = cooldown.remaining_seconds(key)
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail=f"{message} (cooldown : {remaining:.0f}s restantes)",
                headers={"Retry-After": str(int(remaining) + 1)},
            )

    if not limiter.allow(key):
        if progressive:
            penalty = cooldown.register_violation(key)
            raise HTTPException(
                status_code=429,
                detail=f"{message} (cooldown : {penalty:.0f}s)",
                headers={"Retry-After": str(int(penalty) + 1)},
            )
        raise HTTPException(status_code=429, detail=message)

    if progressive:
        cooldown.register_success(key)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _stop_event, _retention_task

    database.init_database()
    logger.info("database initialized")

    _stop_event = asyncio.Event()

    async def _on_temporary_expired():
        """Serveur temporaire (voir `[temporary]`) arrivé en fin de
        vie : purge messages + fichiers puis déclenche l'extinction
        propre du processus. Documenté dans docs/server.md."""

        logger.info("temporary server lifetime reached — wiping data and shutting down")
        try:
            database.delete_all_messages()
            for file_id in database.list_all_files():
                try:
                    file_storage.delete(file_id)
                except (ValueError, OSError):
                    pass
                database.delete_file_record(file_id)
        except Exception:
            logger.exception("échec de la purge du serveur temporaire")

        _stop_event.set()
        # Déclenche l'arrêt propre d'Uvicorn en levant un signal
        # d'interruption dans le thread principal.
        import os
        import signal

        os.kill(os.getpid(), signal.SIGTERM)

    if Config["temporary"]["enabled"]:
        logger.info(
            "serveur temporaire activé : durée de vie %ds", Config["temporary"]["lifetime_seconds"]
        )

    def _handle_sighup() -> None:
        """`kill -HUP <pid>` (ou `anonymous-server reload` / `systemctl
        reload anonymous-server`) déclenche le même rechargement à
        chaud que `/admin/reload`, sans avoir besoin d'une session
        admin — c'est un accès local au processus, pas réseau."""

        logger.info("SIGHUP reçu — rechargement de la configuration")
        try:
            changed_sections = config_module.reload_hot_fields()
            _apply_ratelimit_config(changed_sections)
            if Config["moderation"]["banned_words_enabled"]:
                moderation.load_words(Config["moderation"]["banned_words_file"])
        except config_module.ConfigError as error:
            logger.error("SIGHUP : configuration invalide, ignorée : %s", error)

    try:
        import signal

        asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, _handle_sighup)
    except (NotImplementedError, AttributeError, RuntimeError, ValueError):
        # Windows (pas de SIGHUP), ou boucle asyncio qui ne tourne pas
        # dans le thread principal (ex. certains contextes de test) :
        # le rechargement à chaud reste possible via /admin/reload et
        # la revérification périodique automatique (retention.py),
        # seul le signal SIGHUP direct n'est pas disponible ici.
        pass

    _retention_task = asyncio.create_task(
        run_retention_loop(
            Config,
            file_storage,
            session_registry=session_registry,
            stop_event=_stop_event,
            progressive_cooldowns=_all_cooldowns,
            on_temporary_expired=_on_temporary_expired,
            on_config_reloaded=_apply_ratelimit_config,
        )
    )

    logger.info("server started")

    yield

    _stop_event.set()
    if _retention_task:
        await _retention_task


app = FastAPI(title="Anonymous", version=_SERVER_VERSION, lifespan=lifespan)


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


# ============================================================
# SALONS (rooms) — canaux publics, PAS une identité utilisateur
# ============================================================

def _resolve_room(name: str, password: str | None) -> str:
    """Valide/autorise l'accès à un salon, le crée si la politique du
    serveur l'autorise, et vérifie le mot de passe si le salon en a un.
    Retourne le nom de salon effectif à utiliser. Lève HTTPException en
    cas de refus. Ne stocke, ne journalise et n'expose JAMAIS
    `password` au-delà de cette vérification ponctuelle."""

    rooms_config = Config["rooms"]

    if not rooms_config["enabled"]:
        return rooms_config["default_room"]

    if not name:
        name = rooms_config["default_room"]

    row = database.get_room(name)

    if row is None:
        if not rooms_config["allow_public_rooms"]:
            raise HTTPException(
                status_code=404,
                detail="salon inconnu et création libre désactivée par l'administrateur.",
            )

        if not is_valid_room_name(name, rooms_config["max_room_name_length"]):
            raise HTTPException(status_code=422, detail="nom de salon invalide.")

        if database.count_rooms() >= rooms_config["max_rooms"]:
            raise HTTPException(status_code=403, detail="nombre maximal de salons atteint.")

        row = database.create_room(name, password_hash=None)
        if row is None:
            # Créé entre-temps par une autre requête concurrente — on
            # relit simplement l'état actuel plutôt que d'échouer.
            row = database.get_room(name)

    if row and row.get("password_hash"):
        if not password or not auth.verify_password(password, row["password_hash"]):
            raise HTTPException(
                status_code=401, detail="mot de passe de salon requis ou invalide."
            )

    return name


@app.post("/auth/login")
def login(data: LoginRequest, request: Request):
    if not Config["auth"]["enabled"]:
        raise HTTPException(status_code=400, detail="l'authentification n'est pas activée sur ce serveur.")

    ip = _client_ip(request)
    _check_rate_limit(message_limiter, message_cooldown, f"login:{ip}", "trop de tentatives, réessayez plus tard.")

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
        "server_version": _SERVER_VERSION,
        "auth_required": Config["auth"]["enabled"],
        "max_message_size": Config["messages"]["max_size"],
        "max_file_size": Config["files"]["max_file_size"],
        "files_enabled": Config["files"]["enabled"],
        "key_rotation_messages": Config["crypto"]["key_rotation_messages"],
        "key_rotation_seconds": Config["crypto"]["key_rotation_seconds"],
        "session_ttl_seconds": Config["session"]["ttl_seconds"],
        "features": dict(Config["features"]),
        "e2ee": Config["privacy"]["e2ee"],
        "ratelimit": {
            "messages_per_minute": Config["ratelimit"]["messages_per_minute"],
            "uploads_per_minute": Config["ratelimit"]["uploads_per_minute"],
            # Toujours annoncé, comme demandé : les clients (et les
            # humains) doivent savoir si un cooldown progressif est
            # actif sur ce serveur avant de s'y heurter.
            "progressive_cooldown_enabled": Config["ratelimit"]["progressive_cooldown_enabled"],
        },
        # N'indique QUE le mécanisme (mot de passe requis ou non pour
        # revendiquer le rôle admin), jamais qui est actuellement
        # admin — voir docs/crypto.md "Administration sans identité".
        "admin_password_required": bool(Config["admin"]["password_hash"]),
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
    _check_rate_limit(session_limiter, session_cooldown, ip, "trop de sessions créées, ralentissez.")

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
# ADMINISTRATION ÉPHÉMÈRE — voir docs/crypto.md "Administration sans
# identité" et session.py. Aucun autre client ne peut jamais savoir
# qui est admin : ce statut n'apparaît dans AUCUNE réponse publique
# (enveloppes, /rooms, /status, /api/stats).
# ============================================================

def _verify_admin_action(session_id: str, signature_b64: str, canonical: bytes) -> None:
    try:
        signature_bytes = b64d(signature_b64)
    except Exception:
        raise HTTPException(status_code=422, detail="signature invalide (encodage).")

    if not session_registry.verify_signature(session_id, canonical, signature_bytes):
        raise HTTPException(status_code=401, detail="signature invalide.")

    if not session_registry.is_admin(session_id):
        raise HTTPException(status_code=403, detail="privilèges administrateur requis.")


@app.post("/admin/claim")
def admin_claim(data: AdminClaimRequest, request: Request):
    """Revendique le rôle admin pour la session courante.

    - Si `[admin] password_hash` est configuré : n'importe quelle
      session qui fournit le bon mot de passe devient admin (plusieurs
      sessions peuvent l'être simultanément si le mot de passe est
      partagé — c'est voulu, comme le mot de passe serveur global).
    - Sinon : la PREMIÈRE session qui appelle cet endpoint depuis le
      démarrage du serveur devient admin, définitivement (jusqu'au
      redémarrage). Toute tentative suivante sans mot de passe échoue.
    """

    _require_auth(request.headers.get("authorization"))

    ip = _client_ip(request)
    _check_rate_limit(session_limiter, session_cooldown, f"admin-claim:{ip}", "trop de tentatives, ralentissez.")

    try:
        signature_bytes = b64d(data.signature)
    except Exception:
        raise HTTPException(status_code=422, detail="signature invalide (encodage).")

    if not session_registry.verify_signature(data.session_id, data.canonical_bytes(), signature_bytes):
        raise HTTPException(status_code=401, detail="signature invalide.")

    admin_config = Config["admin"]

    if admin_config["password_hash"]:
        if not data.password or not auth.verify_password(data.password, admin_config["password_hash"]):
            raise HTTPException(status_code=401, detail="mot de passe administrateur incorrect.")
        session_registry.mark_admin(data.session_id)
        return {"is_admin": True}

    if session_registry.try_claim_admin_first(data.session_id):
        return {"is_admin": True}

    raise HTTPException(
        status_code=403,
        detail="un administrateur a déjà été désigné pour cette instance serveur.",
    )


@app.post("/admin/reload")
def admin_reload(data: AdminReloadRequest, request: Request):
    """Recharge à chaud la configuration et la liste de mots bannis,
    sans redémarrer le serveur (équivalent manuel de
    `systemctl reload anonymous-server` / la revérification
    périodique automatique — voir retention.py)."""

    _require_auth(request.headers.get("authorization"))
    _verify_admin_action(data.session_id, data.signature, data.canonical_bytes())

    try:
        changed_sections = config_module.reload_hot_fields()
    except config_module.ConfigError as error:
        raise HTTPException(status_code=400, detail=f"configuration invalide, non appliquée : {error}")

    _apply_ratelimit_config(changed_sections)

    if Config["moderation"]["banned_words_enabled"]:
        moderation.load_words(Config["moderation"]["banned_words_file"])

    logger.info("configuration reloaded via /admin/reload")

    return {"reloaded_sections": changed_sections}


@app.post("/admin/rooms/password")
def admin_set_room_password(data: AdminRoomPasswordRequest, request: Request):
    """Change (ou retire) le mot de passe d'un salon existant SANS
    perdre son historique de messages."""

    _require_auth(request.headers.get("authorization"))
    _verify_admin_action(data.session_id, data.signature, data.canonical_bytes())

    if not is_valid_room_name(data.room, Config["rooms"]["max_room_name_length"]):
        raise HTTPException(status_code=422, detail="nom de salon invalide.")

    password_hash = auth.hash_password(data.password) if data.password else None
    updated = database.set_room_password(data.room, password_hash)

    if not updated:
        raise HTTPException(status_code=404, detail="salon introuvable.")

    return {"room": data.room, "has_password": bool(password_hash)}


# ============================================================
# SALONS — endpoints publics (liste + création explicite)
# ============================================================

@app.get("/rooms")
def list_rooms(request: Request):
    _require_auth(request.headers.get("authorization"))

    rooms_config = Config["rooms"]

    if not rooms_config["enabled"]:
        return {"enabled": False, "rooms": []}

    return {"enabled": True, "rooms": database.list_rooms()}


@app.post("/rooms")
def create_room(data: RoomCreateRequest, request: Request):
    _require_auth(request.headers.get("authorization"))

    rooms_config = Config["rooms"]

    if not rooms_config["enabled"]:
        raise HTTPException(status_code=403, detail="les salons sont désactivés sur ce serveur.")

    if not rooms_config["allow_public_rooms"]:
        raise HTTPException(
            status_code=403,
            detail="la création de salon par les clients est désactivée par l'administrateur.",
        )

    ip = _client_ip(request)
    _check_rate_limit(
        session_limiter, session_cooldown, f"room-create:{ip}", "trop de créations de salon, ralentissez."
    )

    if not is_valid_room_name(data.name, rooms_config["max_room_name_length"]):
        raise HTTPException(status_code=422, detail="nom de salon invalide.")

    if database.count_rooms() >= rooms_config["max_rooms"]:
        raise HTTPException(status_code=403, detail="nombre maximal de salons atteint.")

    password_hash = auth.hash_password(data.password) if data.password else None
    row = database.create_room(data.name, password_hash)

    if row is None:
        raise HTTPException(status_code=409, detail="ce salon existe déjà.")

    return {"name": row["name"], "has_password": bool(row["password_hash"])}


# ============================================================
# BROADCAST WEBSOCKET
# ============================================================

async def broadcast(data: dict, room: str) -> None:
    async with _sockets_lock:
        sockets = [ws for ws, ws_room in _active_sockets.items() if ws_room == room]

    dead = []
    for socket in sockets:
        try:
            await socket.send_json(data)
        except Exception:
            dead.append(socket)

    if dead:
        async with _sockets_lock:
            for socket in dead:
                _active_sockets.pop(socket, None)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    authorization = websocket.headers.get("authorization")

    if Config["auth"]["enabled"]:
        token = auth.extract_bearer_token(authorization)
        if not auth.verify_token(token):
            await websocket.close(code=4401)
            return

    room_name = websocket.query_params.get("room") or Config["rooms"]["default_room"]
    room_password = websocket.query_params.get("room_password")

    try:
        room_name = _resolve_room(room_name, room_password)
    except HTTPException as error:
        await websocket.close(code=4403 if error.status_code in (401, 403) else 4404)
        return

    ip = websocket.client.host if websocket.client else "unknown"

    if not connection_counter.try_acquire(ip):
        await websocket.close(code=4429)
        return

    await websocket.accept()

    async with _sockets_lock:
        _active_sockets[websocket] = room_name

    try:
        while True:
            # Le principal usage de ce canal (dans le sens client ->
            # serveur) est un signal éphémère "en train d'écrire", qui
            # n'est JAMAIS stocké ni journalisé — voir docs/crypto.md
            # "Fonctionnalités et frontière serveur". La création de
            # message reste toujours via POST /messages.
            raw = await websocket.receive_text()

            if len(raw) > 512:
                # Garde-fou anti-abus (voir docs/server.md "Protection
                # WebSocket") : une frame de contrôle n'a jamais besoin
                # d'être grande. Une frame anormalement longue coupe la
                # connexion plutôt que d'être traitée.
                await websocket.close(code=4400)
                return

            if not Config["features"]["typing_indicators_enabled"]:
                continue

            try:
                control = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue

            if control.get("type") != "typing":
                continue

            sender_session_id = control.get("session_id")
            sender_info = session_registry.get(sender_session_id) if sender_session_id else None

            if sender_info is None:
                continue

            await broadcast(
                {
                    "type": "typing_indicator",
                    "room": room_name,
                    "anonymous_number": sender_info.anonymous_number,
                },
                room=room_name,
            )
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        async with _sockets_lock:
            _active_sockets.pop(websocket, None)
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
        "room": message["room"],
    }


# ============================================================
# MESSAGES
# ============================================================

@app.post("/messages")
async def create_new_message(envelope: SignedEnvelopeIn, request: Request):
    _require_auth(request.headers.get("authorization"))

    ip = _client_ip(request)
    _check_rate_limit(message_limiter, message_cooldown, ip, "trop de messages, ralentissez.")

    try:
        envelope.validate_semantics(Config["messages"]["max_size"])
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    if envelope.type == "reaction" and not Config["features"]["reactions_enabled"]:
        raise HTTPException(status_code=403, detail="les réactions sont désactivées sur ce serveur.")

    room_name = _resolve_room(envelope.room, envelope.room_password)

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

    # Mode non-E2EE explicite (voir `[privacy] e2ee` — désactivé par
    # défaut, voir docs/privacy.md). Le serveur ne peut inspecter le
    # contenu QUE dans ce mode, où `ciphertext` transporte en réalité
    # du texte en clair (algorithm="none"). En E2EE (mode par défaut),
    # cette branche n'est jamais atteinte : "none" est refusé plus haut.
    if envelope.algorithm == "none":
        if Config["privacy"]["e2ee"]:
            raise HTTPException(
                status_code=422,
                detail="algorithme en clair refusé : ce serveur exige le chiffrement de bout en bout.",
            )

        if Config["moderation"]["banned_words_enabled"] and moderation.contains_banned_word(
            envelope.ciphertext
        ):
            # Volontairement générique — voir le cahier des charges
            # d'origine : ne jamais révéler QUEL mot a déclenché le
            # rejet, ni à qui appartenait le message.
            raise HTTPException(status_code=422, detail="message rejected")
    elif Config["moderation"]["banned_words_enabled"] and not Config["privacy"]["e2ee"]:
        # e2ee=false mais le client a quand même chiffré : rien à
        # inspecter, on laisse passer (voir docs/privacy.md, la
        # modération réelle exige explicitement algorithm="none").
        pass

    message = database.create_message(
        envelope_type=envelope.type,
        protocol_version=envelope.protocol_version,
        algorithm=envelope.algorithm,
        key_id=envelope.key_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        anonymous_number=session_info.anonymous_number,
        room=room_name,
    )

    public = public_envelope(message)

    await broadcast({"type": "message_created", "envelope": public}, room=room_name)

    return public


@app.get("/messages")
def history(request: Request, limit: int = 50, room: str | None = None, room_password: str | None = None):
    _require_auth(request.headers.get("authorization"))
    limit = max(1, min(limit, 200))

    room_name = _resolve_room(room or Config["rooms"]["default_room"], room_password)

    return {
        "room": room_name,
        "messages": [public_envelope(m) for m in database.get_messages(limit, room=room_name)],
    }


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
    _check_rate_limit(upload_limiter, upload_cooldown, ip, "trop d'envois de fichiers, ralentissez.")

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
# PAGE WEB PUBLIQUE, STATUT, STATISTIQUES, POLITIQUE DE MODÉRATION
# ============================================================
#
# Rien ici n'utilise de ressource externe (pas de CDN, pas de police
# Google, pas d'analytics) — tout est généré localement en HTML/CSS
# minimal. Voir docs/privacy.md : uniquement des agrégats, jamais
# d'identifiant individuel, d'IP, ou d'information système sensible.

def _escape(text: str) -> str:
    import html as html_module

    return html_module.escape(text)


async def _aggregate_stats() -> dict:
    async with _sockets_lock:
        online = len(_active_sockets)

    now = time.time()
    since_midnight = now - (now % 86400)

    return {
        "online": online,
        "rooms": database.count_rooms(),
        "messages_total": database.count_messages(),
        "messages_today": database.count_messages_since(since_midnight),
        "storage_bytes": database.total_storage_bytes(),
    }


def _format_retention() -> str:
    retention = Config["retention"]

    if not retention["enabled"] or retention["max_age_seconds"] <= 0:
        return "illimitée"

    seconds = retention["max_age_seconds"]

    if seconds % 86400 == 0:
        return f"{seconds // 86400} jour(s)"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} heure(s)"
    return f"{seconds} secondes"


@app.get("/api/stats")
async def api_stats():
    stats = await _aggregate_stats()
    return {
        "online": stats["online"],
        "rooms": stats["rooms"],
        "messages": stats["messages_total"],
        "storage_bytes": stats["storage_bytes"],
    }


@app.get("/status", response_class=PlainTextResponse)
async def status_page():
    stats = await _aggregate_stats()
    uptime_seconds = int(time.time() - _server_started_at)
    hours, remainder = divmod(uptime_seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    storage_mb = stats["storage_bytes"] / (1024 * 1024)

    lines = [
        "Anonymous Server",
        "Status: OK",
        "",
        f"Version: {_SERVER_VERSION}",
        "",
        f"Rooms: {stats['rooms']}",
        f"Online: {stats['online']}",
        f"Storage: {storage_mb:.0f} MB",
        "",
        f"Uptime: {hours}h {minutes}m",
    ]
    return "\n".join(lines)


@app.get("/policy")
def get_policy():
    """Politique de modération PUBLIQUE, destinée à être appliquée par
    les CLIENTS avant chiffrement (voir docs/crypto.md et
    docs/privacy.md) : quand `e2ee=true` (par défaut), le serveur ne
    peut structurellement pas vérifier son application. Ce n'est
    JAMAIS une garantie — un client modifié peut toujours l'ignorer."""

    moderation_config = Config["moderation"]
    enabled = moderation_config["banned_words_enabled"]

    return {
        "e2ee": Config["privacy"]["e2ee"],
        "banned_words_enabled": enabled,
        "banned_words": moderation.current_words() if enabled else [],
        "enforced_server_side": enabled and not Config["privacy"]["e2ee"],
        "note": (
            "Politique indicative pour un filtrage côté client avant chiffrement. "
            "Si e2ee=true, le serveur ne peut PAS vérifier son respect : "
            "un client modifié peut toujours l'ignorer."
        ),
    }


@app.get("/", response_class=HTMLResponse)
async def web_status_page():
    web_config = Config["web"]

    if not web_config["enabled"] or not web_config["public_page"]:
        return HTMLResponse("<!DOCTYPE html><html><body><p>Anonymous Server</p></body></html>")

    stats = await _aggregate_stats()

    sections = ["<p><strong>Status :</strong> Online</p>"]

    if web_config["show_online_count"]:
        sections.append(f"<p><strong>Utilisateurs en ligne :</strong> {stats['online']}</p>")

    if web_config["show_room_counts"] and Config["rooms"]["enabled"]:
        rows = "".join(
            f"<tr><td>{_escape(room['name'])}</td><td>{room['message_count']}</td>"
            f"<td>{'🔒' if room['has_password'] else ''}</td></tr>"
            for room in database.list_rooms()[:25]
        ) or "<tr><td colspan='3'><em>Aucun salon pour l'instant</em></td></tr>"
        sections.append(f"<h2>Salons</h2><table>{rows}</table>")

    if web_config["show_message_count"]:
        sections.append(f"<p><strong>Messages aujourd'hui :</strong> {stats['messages_today']}</p>")

    if web_config["show_storage_usage"]:
        max_bytes = Config["storage"]["max_storage_bytes"]
        sections.append(
            f"<p><strong>Stockage :</strong> {stats['storage_bytes'] / 1024 / 1024:.0f} Mo / "
            f"{max_bytes / 1024 / 1024:.0f} Mo</p>"
        )

    sections.append(f"<p><strong>Rétention :</strong> {_format_retention()}</p>")
    sections.append(
        f"<p><strong>Fichiers :</strong> {'activés' if Config['files']['enabled'] else 'désactivés'}</p>"
    )
    sections.append(
        f"<p><strong>Mot de passe serveur :</strong> "
        f"{'requis' if Config['auth']['enabled'] else 'non requis'}</p>"
    )

    server_name = _escape(web_config["server_name"])
    description = _escape(web_config["description"])
    body = "\n".join(sections)

    html_doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{server_name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 640px;
          margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0; }}
  td {{ padding: 0.3rem 0.6rem; border-bottom: 1px solid #eee; }}
  footer {{ margin-top: 2.5rem; font-size: 0.8rem; color: #888; }}
</style>
</head>
<body>
<h1>{server_name}</h1>
<p>{description}</p>
{body}
<footer>Propulsé par Anonymous — chiffrement de bout en bout, aucun
tracking, aucune ressource externe, aucune identité stockée.</footer>
</body>
</html>"""

    return HTMLResponse(html_doc)


# ============================================================
# DÉMARRAGE
# ============================================================

def _pidfile_path() -> str:
    storage_dir = os.path.dirname(os.path.abspath(Config["storage"]["database"])) or "."
    return os.path.join(storage_dir, "anonymous-server.pid")


def _cli_hash_password() -> None:
    import getpass

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


def _cli_hash_admin_password() -> None:
    import getpass

    password = getpass.getpass("Mot de passe administrateur : ")
    confirm = getpass.getpass("Confirmez : ")

    if password != confirm:
        print("Les mots de passe ne correspondent pas.")
        sys.exit(1)

    print()
    print("Ajoutez ceci à server.toml :")
    print()
    print("[admin]")
    print(f'password_hash = "{auth.hash_password(password)}"')
    print()
    print("Sans cette ligne, la PREMIÈRE session qui demande le rôle")
    print("admin l'obtient automatiquement, sans mot de passe (voir")
    print("docs/crypto.md \"Administration sans identité\").")


def _cli_check_config() -> None:
    if config_module._load_error is not None:
        print(f"Configuration INVALIDE ({config_module._config_file_path}) :")
        print(f"  {config_module._load_error}")
        sys.exit(1)

    path = config_module._config_file_path
    print(f"Configuration valide : {path if path else '(valeurs par défaut, aucun fichier trouvé)'}")
    sys.exit(0)


def _cli_stats() -> None:
    if config_module._load_error is not None:
        print(f"Configuration invalide, impossible de lire les statistiques : {config_module._load_error}")
        sys.exit(1)

    database.init_database()

    print(f"Version         : {_SERVER_VERSION}")
    print(f"Base de données : {Config['storage']['database']}")
    print(f"Salons          : {database.count_rooms()}")
    print(f"Messages        : {database.count_messages()}")
    print(f"Stockage        : {database.total_storage_bytes() / 1024 / 1024:.1f} Mo")


def _cli_cleanup() -> None:
    if config_module._load_error is not None:
        print(f"Configuration invalide, aucun nettoyage effectué : {config_module._load_error}")
        sys.exit(1)

    database.init_database()
    storage = FileStorage(
        Config["storage"]["files"], Config["files"]["max_file_size"], Config["storage"]["max_storage_bytes"]
    )
    run_retention_once(Config["retention"], Config["messages"], storage)
    print("Passage de rétention effectué.")


def _cli_reload_signal() -> None:
    import signal

    path = _pidfile_path()

    if not os.path.exists(path):
        print(f"Aucun fichier PID trouvé ({path}) — le serveur tourne-t-il ?")
        print("Alternative : sudo systemctl reload anonymous-server")
        sys.exit(1)

    try:
        pid = int(open(path).read().strip())
        os.kill(pid, signal.SIGHUP)
        print(f"Signal de rechargement envoyé au processus {pid}.")
    except AttributeError:
        print("Le rechargement par signal n'est pas disponible sur cette plateforme (Windows).")
        print("Redémarrez le service pour appliquer la nouvelle configuration.")
        sys.exit(1)
    except (ValueError, OSError) as error:
        print(f"Impossible d'envoyer le signal : {error}")
        sys.exit(1)


def _cli_config_wizard() -> None:
    import config_wizard

    path = config_module._config_file_path
    output_path = str(path) if path else "server.toml"

    base_config = Config if config_module._load_error is None else config_module.DEFAULTS

    print(f"Assistant de configuration — écrira dans : {output_path}")
    print("(appuyez sur une touche pour continuer, Ctrl+C pour annuler)")

    try:
        config_wizard.run_wizard(base_config, output_path)
    except KeyboardInterrupt:
        print("Annulé.")


def _run_server() -> None:
    if config_module._load_error is not None:
        print(f"Configuration invalide, démarrage annulé : {config_module._load_error}", file=sys.stderr)
        print("Utilisez 'anonymous-server check-config' pour plus de détails.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(_pidfile_path(), "w") as handle:
            handle.write(str(os.getpid()))
    except OSError:
        pass  # non bloquant : seul `anonymous-server reload` en a besoin

    access_log = Config["logging"]["access_logs"]

    try:
        uvicorn.run(
            app,
            host=Config["server"]["host"],
            port=Config["server"]["port"],
            access_log=access_log,
            log_level="info",
        )
    finally:
        try:
            os.remove(_pidfile_path())
        except OSError:
            pass


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="anonymous-server",
        description="Serveur relais chiffré Anonymous — sans identité applicative.",
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"anonymous-server {_SERVER_VERSION}"
    )
    parser.add_argument(
        "--config", "-c", metavar="PATH",
        help="Chemin vers server.toml (déjà pris en compte si passé avant les autres options).",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("hash-password", help="Génère le hash Argon2id du mot de passe serveur.")
    subparsers.add_parser(
        "generate-admin-password-hash", help="Génère le hash Argon2id du mot de passe administrateur."
    )
    subparsers.add_parser("check-config", help="Valide server.toml et quitte sans démarrer le serveur.")
    subparsers.add_parser("stats", help="Affiche les statistiques agrégées et quitte.")
    subparsers.add_parser("cleanup", help="Exécute un passage de rétention immédiat et quitte.")
    subparsers.add_parser("reload", help="Envoie un signal de rechargement au serveur déjà lancé.")
    subparsers.add_parser("config", help="Assistant de configuration interactif (TUI).")

    args = parser.parse_args()

    dispatch = {
        "hash-password": _cli_hash_password,
        "generate-admin-password-hash": _cli_hash_admin_password,
        "check-config": _cli_check_config,
        "stats": _cli_stats,
        "cleanup": _cli_cleanup,
        "reload": _cli_reload_signal,
        "config": _cli_config_wizard,
    }

    dispatch.get(args.command, _run_server)()


if __name__ == "__main__":
    main()
