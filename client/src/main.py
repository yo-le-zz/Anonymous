import asyncio
import curses
import json
import mimetypes
import os
import threading
import time
import traceback
from math import ceil
from pathlib import Path

import requests
import websockets

from config import Config
from crypto import (
    DEFAULT_ALGORITHM,
    DecryptionError,
    Envelope,
    EpochKeyring,
    KeyExchangeState,
    Room,
    RotationPolicy,
    SigningIdentity,
    admin_canonical_bytes,
    b64d,
    b64e,
    canonical_envelope_bytes,
    finish_key_exchange,
    parse_key_id as _parse_key_id_public,
    start_key_exchange,
)
from framing import frame_chunks, unframe_stream
from media import decrypt_file_chunks, encrypt_file_chunks, save_stream_to_path
from protocol import (
    FileMetadataPayload,
    ReactionPayload,
    TextPayload,
    build_ws_url,
    is_insecure,
    normalize_server_url,
)
from storage import ClientStore

# ============================================================
# ÉTAT GLOBAL
# ============================================================

store = ClientStore()

messages: list[dict] = []
messages_lock = threading.Lock()
draw_lock = threading.Lock()

screen = None
running = True

state_lock = threading.Lock()
server_url: str | None = None
auth_token: str | None = None
current_room_name: str | None = None
current_room: Room | None = None
keyring: EpochKeyring | None = None
pending_exchange: KeyExchangeState | None = None

# Identité de session éphémère (voir docs/crypto.md, "Session éphémère
# et signature"). Régénérée à chaque `/connect` : jamais persistée,
# jamais réutilisée d'une session à l'autre.
signing_identity: SigningIdentity | None = None
session_id: str | None = None
own_anonymous_number: int | None = None
is_admin: bool = False  # jamais annoncé au serveur ni visible des autres

# Pseudos + couleurs LOCAUX pour d'autres numéros "Anonymous #XXXXXX"
# vus pendant la session en cours. JAMAIS envoyé au serveur, JAMAIS
# persisté entre sessions : puisque le numéro change à chaque
# connexion (voir docs/crypto.md), le conserver d'une session à
# l'autre étiquetterait à tort une personne différente. C'est un
# simple confort d'affichage local, valable seulement pour la
# connexion en cours.
local_nicknames: dict[int, tuple[str, str]] = {}  # numéro -> (nom, couleur)
NICKNAME_COLORS = ("cyan", "green", "yellow", "magenta", "white", "red")

# Signal (thread-safe) qu'un indicateur "en train d'écrire" doit être
# envoyé au prochain passage de la boucle WebSocket — voir
# input_loop() et websocket_listener_async().
_typing_signal = threading.Event()

ws_generation = 0  # incrémenté à chaque /connect ou /disconnect pour
                   # invalider proprement le thread WebSocket précédent


# ============================================================
# UTILITAIRES D'ÉTAT
# ============================================================

def set_room(name: str, room: Room) -> None:
    global current_room_name, current_room, keyring, ws_generation

    with state_lock:
        current_room_name = name
        current_room = room
        keyring = EpochKeyring(
            room,
            RotationPolicy(
                max_messages=Config.get("crypto", {}).get("key_rotation_messages", 100),
                max_seconds=Config.get("crypto", {}).get("key_rotation_seconds", 3600),
            ),
        )
        # Le WebSocket est abonné à UN SEUL salon à la fois (voir
        # docs/crypto.md) : changer de salon actif invalide la
        # connexion en cours et force une reconnexion abonnée au
        # nouveau salon, sinon les messages temps réel du nouveau
        # salon ne seraient jamais reçus.
        should_reconnect = server_url is not None
        ws_generation += 1
        my_generation = ws_generation

    if should_reconnect:
        threading.Thread(
            target=websocket_listener, args=(my_generation,), daemon=True
        ).start()


def http_headers() -> dict:
    if auth_token:
        return {"Authorization": f"Bearer {auth_token}"}
    return {}


# ============================================================
# PRÉPARATION DES MESSAGES POUR AFFICHAGE
# ============================================================

def _format_display_name(anonymous_number, my_number) -> str:
    """Numéro pseudonyme de session, PAS un username (voir docs/crypto.md).
    Affiche "Vous / Anonymous #NNNNNN" pour les messages de la propre
    session courante, "Anonymous #NNNNNN" sinon — sauf si un pseudo
    LOCAL a été défini pour ce numéro (/nick), auquel cas il est
    utilisé à la place, avec sa couleur (voir draw_chat)."""

    if anonymous_number is None:
        return "Anonymous #??????"

    nickname_entry = local_nicknames.get(anonymous_number)
    label = nickname_entry[0] if nickname_entry else f"Anonymous #{anonymous_number:06d}"

    if my_number is not None and anonymous_number == my_number:
        return f"Vous / {label}"

    return label


def prepare_incoming(envelope_dict: dict) -> dict:
    """Tente de déchiffrer une enveloppe reçue du serveur. Un message
    qu'on ne peut pas déchiffrer (mauvais salon / epoch inconnue /
    corrompu) est affiché comme indisponible, jamais comme une
    erreur serveur : le serveur n'a fait que relayer un blob opaque."""

    entry = {
        "id": envelope_dict.get("id"),
        "created_at": envelope_dict.get("created_at", ""),
        "anonymous_number": envelope_dict.get("anonymous_number"),
    }

    with state_lock:
        active_keyring = keyring
        my_number = own_anonymous_number

    entry["display_name"] = _format_display_name(entry["anonymous_number"], my_number)

    if active_keyring is None:
        entry["content"] = "[aucun salon actif — /room use pour en choisir un]"
        entry["unavailable"] = True
        return entry

    try:
        envelope = Envelope.from_dict(envelope_dict)
    except (KeyError, ValueError):
        entry["content"] = "[message chiffré indisponible]"
        entry["unavailable"] = True
        return entry

    try:
        from crypto import decrypt_message

        plaintext = decrypt_message(active_keyring, envelope)
    except DecryptionError:
        entry["content"] = "[message chiffré indisponible]"
        entry["unavailable"] = True
        return entry

    if envelope.type == "msg":
        try:
            payload = TextPayload.decode(plaintext)
            # `reply_to` est purement indicatif (voir protocol.py) :
            # jamais vérifié, juste un confort d'affichage.
            if payload.reply_to is not None:
                entry["content"] = f"↳ (#{payload.reply_to}) {payload.body}"
            else:
                entry["content"] = payload.body
        except (json.JSONDecodeError, KeyError):
            entry["content"] = "[message chiffré indisponible]"
            entry["unavailable"] = True
        return entry

    if envelope.type == "reaction":
        try:
            reaction = ReactionPayload.decode(plaintext)
            entry["content"] = f"{reaction.emoji} en réaction à #{reaction.target_id}"
            entry["is_reaction"] = True
        except (json.JSONDecodeError, KeyError):
            entry["content"] = "[réaction indisponible]"
            entry["unavailable"] = True
        return entry

    if envelope.type == "file":
        try:
            meta = FileMetadataPayload.decode(plaintext)
            kind = "Image" if meta.mime_type.startswith("image/") else (
                "Video" if meta.mime_type.startswith("video/") else "File"
            )
            entry["content"] = f"[{kind}] {meta.filename} ({meta.size_bytes} octets) — /download {meta.file_id}"
            entry["file_meta"] = meta.encode().decode("utf-8")
            # L'epoch utilisée pour chiffrer les blocs du fichier est la
            # même que celle du message d'enveloppe qui transporte ses
            # métadonnées : on la garde pour pouvoir re-dériver la même
            # clé de fichier au moment du téléchargement.
            _, epoch = _parse_key_id_public(envelope.key_id)
            entry["file_epoch"] = epoch
        except (json.JSONDecodeError, KeyError):
            entry["content"] = "[message chiffré indisponible]"
            entry["unavailable"] = True
        return entry

    entry["content"] = "[type de message inconnu]"
    entry["unavailable"] = True
    return entry


def add_local_message(entry: dict) -> None:
    with messages_lock:
        for existing in messages:
            if existing.get("id") == entry.get("id") and entry.get("id") is not None:
                return
        messages.append(entry)


def show_system_message(text: str) -> None:
    with messages_lock:
        messages.append({"id": None, "content": text, "system": True})


# ============================================================
# RÉSEAU — HTTP
# ============================================================

def establish_session(base_url: str) -> None:
    """Génère une nouvelle identité de signature Ed25519 EN MÉMOIRE
    (jamais persistée) et l'enregistre auprès du serveur pour obtenir
    un nouveau session_id + un nouveau numéro "Anonymous #XXXXXX".

    Appelée à chaque `/connect` et automatiquement en cas
    d'expiration de session détectée par le serveur : dans les deux
    cas, une IDENTITÉ VISUELLE NOUVELLE est obtenue, jamais l'ancienne
    restaurée."""

    global signing_identity, session_id, own_anonymous_number, is_admin

    identity = SigningIdentity()

    response = requests.post(
        f"{base_url}/session",
        json={"public_key": b64e(identity.public_key_bytes())},
        headers=http_headers(),
        timeout=Config["network"]["connect_timeout_seconds"],
    )
    response.raise_for_status()
    data = response.json()

    with state_lock:
        signing_identity = identity
        session_id = data["session_id"]
        is_admin = False
        own_anonymous_number = data["anonymous_number"]

    show_system_message(f"Identité de session : Anonymous #{own_anonymous_number:06d}")


def _build_signed_body(envelope: Envelope) -> dict:
    with state_lock:
        sid = session_id
        identity = signing_identity
        room_name = current_room_name

    if sid is None or identity is None:
        raise RuntimeError("aucune session active — /connect d'abord.")

    signature = identity.sign(canonical_envelope_bytes(envelope))

    body = envelope.to_dict()
    body["session_id"] = sid
    body["signature"] = b64e(signature)
    body["room"] = room_name or "general"
    body["room_password"] = store.get_room_password(room_name) if room_name else None
    return body


def post_signed_envelope(base_url: str, envelope: Envelope):
    """POST /messages avec preuve de session, et renouvellement
    automatique et transparent de la session si le serveur la
    considère expirée/inconnue (401) — une seule tentative de reprise,
    pour ne jamais boucler indéfiniment."""

    body = _build_signed_body(envelope)

    response = requests.post(
        f"{base_url}/messages",
        json=body,
        headers=http_headers(),
        timeout=Config["network"]["connect_timeout_seconds"],
    )

    if response.status_code == 401:
        show_system_message("Session expirée : renouvellement automatique...")
        establish_session(base_url)
        body = _build_signed_body(envelope)
        response = requests.post(
            f"{base_url}/messages",
            json=body,
            headers=http_headers(),
            timeout=Config["network"]["connect_timeout_seconds"],
        )

    response.raise_for_status()
    return response


def send_text_message(text: str) -> None:
    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None:
        show_system_message("Aucun serveur connecté. /connect URL")
        return

    if active_keyring is None:
        show_system_message("Aucun salon actif. /room new ou /room join.")
        return

    from crypto import encrypt_message

    envelope = encrypt_message(active_keyring, TextPayload(body=text).encode())

    response = post_signed_envelope(base_url, envelope)

    # Affichage immédiat : on n'attend pas la diffusion WebSocket pour
    # montrer son propre message (celle-ci reste le mécanisme normal
    # pour les AUTRES clients, et reste utilisée en repli si jamais
    # elle n'était pas déjà affichée — la déduplication par id dans
    # `add_local_message` rend les deux chemins sûrs ensemble).
    try:
        add_local_message(prepare_incoming(response.json()))
    except Exception:
        pass


def fetch_history(limit: int = 50) -> None:
    with state_lock:
        base_url = server_url
        room_name = current_room_name

    if base_url is None:
        return

    try:
        response = requests.get(
            f"{base_url}/messages",
            params={
                "limit": limit,
                "room": room_name or "general",
                "room_password": store.get_room_password(room_name) if room_name else None,
            },
            headers=http_headers(),
            timeout=Config["network"]["connect_timeout_seconds"],
        )
        response.raise_for_status()

        history = response.json()["messages"]
        prepared = [prepare_incoming(item) for item in history]

        with messages_lock:
            messages.clear()
            messages.extend(prepared)

    except Exception as error:
        show_system_message(f"Erreur de récupération de l'historique : {error}")


def do_login(base_url: str, password: str) -> str:
    response = requests.post(
        f"{base_url}/auth/login",
        json={"password": password},
        timeout=Config["network"]["connect_timeout_seconds"],
    )
    response.raise_for_status()
    return response.json()["token"]


# ============================================================
# COMMANDE : /connect
# ============================================================

def handle_connect(args: list[str]) -> None:
    global server_url, auth_token, ws_generation

    if not args:
        show_system_message("Utilisation : /connect http://host:port [mot_de_passe]")
        return

    try:
        url = normalize_server_url(args[0])
    except ValueError as error:
        show_system_message(str(error))
        return

    if is_insecure(url):
        show_system_message(
            "⚠ Connexion en HTTP (non chiffré au niveau transport). "
            "Utilisez https:// derrière un reverse proxy sur un réseau non fiable."
        )

    token = None

    try:
        info = requests.get(
            f"{url}/server-info",
            timeout=Config["network"]["connect_timeout_seconds"],
        )

        if info.status_code == 401 or (info.ok and info.json().get("auth_required")):
            password = args[1] if len(args) > 1 else None

            if password is None:
                show_system_message(
                    "Ce serveur demande un mot de passe : /connect URL mot_de_passe"
                )
                return

            token = do_login(url, password)

    except requests.RequestException as error:
        show_system_message(f"Impossible de joindre le serveur : {error}")
        return

    with state_lock:
        server_url = url
        auth_token = token
        ws_generation += 1
        my_generation = ws_generation

    show_system_message(f"Connecté à {url}")

    try:
        establish_session(url)
    except requests.RequestException as error:
        show_system_message(f"Impossible d'établir une session (identité) : {error}")
        return

    fetch_history()

    thread = threading.Thread(
        target=websocket_listener, args=(my_generation,), daemon=True
    )
    thread.start()


def handle_disconnect() -> None:
    global server_url, auth_token, ws_generation, signing_identity, session_id, own_anonymous_number, is_admin

    with state_lock:
        server_url = None
        auth_token = None
        ws_generation += 1
        # La session éphémère disparaît immédiatement de la mémoire :
        # elle n'a plus de sens sans serveur associé, et on ne veut
        # jamais la réutiliser telle quelle lors d'une reconnexion.
        signing_identity = None
        session_id = None
        own_anonymous_number = None
        is_admin = False

    show_system_message("Déconnecté.")


# ============================================================
# COMMANDE : /room
# ============================================================

def handle_room(args: list[str]) -> None:
    if not args:
        show_system_message(
            "Utilisation : /room new|join|use|list|password|exchange [...]"
        )
        return

    sub = args[0].lower()

    if sub == "new":
        if len(args) < 2:
            show_system_message("Utilisation : /room new <nom> [mot_de_passe_de_salon]")
            return

        name = args[1]
        password = args[2] if len(args) > 2 else None

        room = Room.create_new()
        store.save_room(name, room, server_password=password)

        with state_lock:
            base_url = server_url

        # IMPORTANT : si un mot de passe est demandé, la création
        # EXPLICITE côté serveur doit se faire AVANT `set_room()` —
        # celui-ci déclenche une reconnexion WebSocket qui, elle,
        # créerait automatiquement le salon en PUBLIC s'il n'existe
        # pas encore (comportement voulu pour la création libre, mais
        # qui gagnerait la course face à une création explicite faite
        # après coup, laissant le salon public malgré le mot de passe
        # demandé).
        if base_url is not None:
            try:
                response = requests.post(
                    f"{base_url}/rooms",
                    json={"name": name, "password": password},
                    headers=http_headers(),
                    timeout=Config["network"]["connect_timeout_seconds"],
                )
                if response.status_code == 200:
                    visibility = "privé (mot de passe)" if password else "public"
                    show_system_message(f"Salon '{name}' enregistré sur le serveur ({visibility}).")
                elif response.status_code == 409:
                    show_system_message(
                        f"Le salon '{name}' existe déjà sur ce serveur — "
                        "utilisez /room password si un mot de passe est requis."
                    )
                else:
                    show_system_message(f"Le serveur a refusé la création du salon : {response.text}")
            except requests.RequestException as error:
                show_system_message(f"Impossible de contacter le serveur pour créer le salon : {error}")

        set_room(name, room)
        show_system_message(f"Salon '{name}' créé. Empreinte : {room.fingerprint()}")
        show_system_message(
            f"Invite à partager HORS BANDE (jamais via ce chat) : {room.to_invite()}"
        )
        return

    if sub == "join":
        if len(args) < 2:
            show_system_message("Utilisation : /room join <invite> [nom] [mot_de_passe_de_salon]")
            return

        try:
            room = Room.from_invite(args[1])
        except ValueError as error:
            show_system_message(f"Invite invalide : {error}")
            return

        name = args[2] if len(args) > 2 else "default"
        password = args[3] if len(args) > 3 else None

        store.save_room(name, room, server_password=password)
        set_room(name, room)
        show_system_message(f"Salon '{name}' importé. Empreinte : {room.fingerprint()}")
        fetch_history()
        return

    if sub == "use":
        if len(args) < 2:
            show_system_message("Utilisation : /room use <nom>")
            return

        rooms = store.load_rooms()
        room = rooms.get(args[1])

        if room is None:
            show_system_message(f"Salon inconnu : {args[1]}")
            return

        set_room(args[1], room)
        show_system_message(f"Salon actif : {args[1]} ({room.fingerprint()})")
        fetch_history()
        return

    if sub == "password":
        if len(args) < 2:
            show_system_message("Utilisation : /room password <nom> [mot_de_passe]")
            return

        name = args[1]
        password = args[2] if len(args) > 2 else None
        rooms = store.load_rooms()

        if name not in rooms:
            show_system_message(
                f"Salon local inconnu : {name}. Utilisez /room new ou /room join d'abord."
            )
            return

        store.save_room(name, rooms[name], server_password=password)
        show_system_message(
            f"Mot de passe de salon {'défini' if password else 'retiré'} pour '{name}' "
            "(mémorisé localement, jamais envoyé qu'au serveur concerné)."
        )
        return

    if sub == "list":
        rooms = store.load_rooms()

        if rooms:
            show_system_message("Salons connus localement (secret de chiffrement) :")
            for name in rooms:
                marker = "*" if name == current_room_name else " "
                show_system_message(f" {marker} {name}")
        else:
            show_system_message("Aucun salon local enregistré.")

        with state_lock:
            base_url = server_url

        if base_url is None:
            show_system_message("(Connectez-vous avec /connect pour voir les salons du serveur.)")
            return

        try:
            response = requests.get(
                f"{base_url}/rooms",
                headers=http_headers(),
                timeout=Config["network"]["connect_timeout_seconds"],
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("enabled", True):
                show_system_message("Les salons sont désactivés sur ce serveur.")
                return

            server_rooms = data.get("rooms", [])
            if not server_rooms:
                show_system_message("Aucun salon sur ce serveur pour l'instant.")
                return

            show_system_message("Salons disponibles sur le serveur :")
            for room_info in server_rooms:
                lock = "🔒" if room_info["has_password"] else "  "
                show_system_message(
                    f" {lock} {room_info['name']} — {room_info['message_count']} message(s)"
                )
            show_system_message(
                "Pour rejoindre : /room join <invite> <nom>, ou /room use <nom> "
                "si vous avez déjà le secret localement."
            )
        except requests.RequestException as error:
            show_system_message(f"Impossible de récupérer la liste des salons du serveur : {error}")
        return

    if sub == "exchange":
        handle_room_exchange(args[1:])
        return

    show_system_message(f"Sous-commande /room inconnue : {sub}")


def handle_room_exchange(args: list[str]) -> None:
    global pending_exchange

    if not args or args[0] == "start":
        state = start_key_exchange()

        with state_lock:
            pending_exchange = state

        show_system_message(
            "Échange démarré. Transmettez ce code à votre correspondant "
            "PAR UN AUTRE CANAL, puis demandez-lui de faire "
            "'/room exchange finish <code>' :"
        )
        show_system_message(
            f"{state.exchange_id.hex()}:{state.public_bytes().hex()}"
        )
        show_system_message(
            "Une fois qu'il vous répond avec son propre code, "
            "faites '/room exchange finish <son_code>'."
        )
        return

    if args[0] == "finish":
        if len(args) < 2:
            show_system_message("Utilisation : /room exchange finish <exchange_id_hex>:<pubkey_hex> [nom]")
            return

        try:
            exchange_id_hex, _, peer_pub_hex = args[1].partition(":")
            peer_public_bytes = bytes.fromhex(peer_pub_hex)
        except ValueError:
            show_system_message("Code d'échange invalide.")
            return

        with state_lock:
            state = pending_exchange

        if state is None or state.exchange_id.hex() != exchange_id_hex:
            show_system_message(
                "Aucun échange correspondant en cours. Lancez d'abord "
                "'/room exchange start' si vous êtes l'initiateur, sinon "
                "renvoyez votre propre code à votre correspondant en retour."
            )
            # Toujours possible de répondre en initiant SA PROPRE moitié :
            # on démarre un nouvel état côté "répondeur" avec le même
            # exchange_id fourni par l'initiateur pour que les deux
            # parties dérivent le même secret.
            return

        room = finish_key_exchange(state, peer_public_bytes)

        name = args[2] if len(args) > 2 else "default"
        store.save_room(name, room)
        set_room(name, room)

        with state_lock:
            pending_exchange = None

        show_system_message(
            f"Salon '{name}' établi par échange X25519. "
            f"Comparez cette empreinte de vive voix avec votre correspondant : {room.fingerprint()}"
        )
        return

    if args[0] == "respond":
        # Le second participant : il a reçu "exchange_id:pubkey" de
        # l'initiateur, génère sa propre paire, calcule le secret, et
        # doit renvoyer sa clé publique à l'initiateur (hors bande).
        if len(args) < 2:
            show_system_message("Utilisation : /room exchange respond <exchange_id_hex>:<pubkey_hex> [nom]")
            return

        try:
            exchange_id_hex, _, peer_pub_hex = args[1].partition(":")
            exchange_id = bytes.fromhex(exchange_id_hex)
            peer_public_bytes = bytes.fromhex(peer_pub_hex)
        except ValueError:
            show_system_message("Code d'échange invalide.")
            return

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        my_state = KeyExchangeState(exchange_id=exchange_id, private_key=X25519PrivateKey.generate())
        room = finish_key_exchange(my_state, peer_public_bytes)

        name = args[2] if len(args) > 2 else "default"
        store.save_room(name, room)
        set_room(name, room)

        show_system_message(
            f"Salon '{name}' établi. Renvoyez ce code à l'initiateur pour "
            f"qu'il finalise (/room exchange finish) : "
            f"{exchange_id_hex}:{my_state.public_bytes().hex()}"
        )
        show_system_message(
            f"Comparez cette empreinte de vive voix : {room.fingerprint()}"
        )
        return

    show_system_message("Sous-commande inconnue. Utilisez start / respond / finish.")


# ============================================================
# COMMANDE : /upload et /download
# ============================================================

def handle_upload(path_str: str) -> None:
    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None:
        show_system_message("Aucun serveur connecté.")
        return

    if active_keyring is None:
        show_system_message("Aucun salon actif.")
        return

    path = Path(path_str).expanduser()

    if not path.is_file():
        show_system_message(f"Fichier introuvable : {path}")
        return

    if path.stat().st_size == 0:
        show_system_message("Impossible d'envoyer un fichier vide.")
        return

    def worker():
        try:
            size = path.stat().st_size
            chunk_count = max(1, ceil(size / (1024 * 1024)))
            epoch = active_keyring.current_epoch()

            with open(path, "rb") as handle:
                file_nonce, _, chunk_generator = encrypt_file_chunks(
                    handle, active_keyring, epoch
                )

                body = frame_chunks(chunk_generator)

                response = requests.post(
                    f"{base_url}/files",
                    data=body,
                    headers={**http_headers(), "Content-Type": "application/octet-stream"},
                    timeout=None,
                )
                response.raise_for_status()
                file_id = response.json()["file_id"]

            mime_type, _ = mimetypes.guess_type(path.name)

            meta = FileMetadataPayload(
                file_id=file_id,
                filename=path.name,
                mime_type=mime_type or "application/octet-stream",
                size_bytes=size,
                chunk_count=chunk_count,
                file_nonce=file_nonce.hex(),
            )

            from crypto import encrypt_message

            envelope = encrypt_message(
                active_keyring, meta.encode(), envelope_type="file"
            )

            response = post_signed_envelope(base_url, envelope)

            try:
                add_local_message(prepare_incoming(response.json()))
            except Exception:
                pass

            show_system_message(f"Fichier envoyé : {path.name}")

        except requests.HTTPError as error:
            detail = error.response.text if error.response is not None else str(error)
            show_system_message(f"Upload refusé : {detail}")
        except Exception as error:
            show_system_message(f"Erreur d'upload : {error}")

    threading.Thread(target=worker, daemon=True).start()


def handle_download(file_id: str) -> None:
    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    meta_json = None
    file_epoch = None
    with messages_lock:
        for entry in messages:
            if entry.get("file_meta"):
                try:
                    candidate = FileMetadataPayload.decode(entry["file_meta"].encode("utf-8"))
                    if candidate.file_id == file_id:
                        meta_json = candidate
                        file_epoch = entry.get("file_epoch")
                        break
                except Exception:
                    continue

    if meta_json is None or file_epoch is None:
        show_system_message("Métadonnées de fichier introuvables localement.")
        return

    def worker():
        try:
            response = requests.get(
                f"{base_url}/files/{file_id}",
                headers=http_headers(),
                stream=True,
                timeout=None,
            )
            response.raise_for_status()

            raw_chunks = response.iter_content(chunk_size=65536)
            encrypted_chunks = unframe_stream(raw_chunks)

            plain_chunks = decrypt_file_chunks(
                encrypted_chunks,
                active_keyring,
                file_epoch,
                bytes.fromhex(meta_json.file_nonce),
                meta_json.chunk_count,
            )

            destination = store.downloads_dir / f"{file_id}_{meta_json.filename}"
            save_stream_to_path(plain_chunks, destination)

            show_system_message(
                f"Téléchargé : {destination} (ouvrez-le manuellement, "
                "il ne sera jamais lancé automatiquement)"
            )

        except Exception as error:
            show_system_message(f"Erreur de téléchargement : {error}")

    threading.Thread(target=worker, daemon=True).start()


# ============================================================
# WEBSOCKET
# ============================================================

async def websocket_listener_async(my_generation: int):
    backoff = Config["network"]["reconnect_backoff_seconds"]
    max_backoff = Config["network"]["reconnect_backoff_max_seconds"]
    consecutive_failures = 0

    while running:
        with state_lock:
            if ws_generation != my_generation or server_url is None:
                return
            base_url = server_url
            room_name = current_room_name
            token = auth_token

        room_password = store.get_room_password(room_name) if room_name else None
        url = build_ws_url(base_url, room=room_name or "general", room_password=room_password)
        headers = {"Authorization": f"Bearer {token}"} if token else {}

        try:
            connect_kwargs = dict(ping_interval=20, ping_timeout=20)

            try:
                connector = websockets.connect(url, additional_headers=headers, **connect_kwargs)
            except TypeError:
                connector = websockets.connect(url, extra_headers=headers, **connect_kwargs)

            async with connector as websocket:
                backoff = Config["network"]["reconnect_backoff_seconds"]
                consecutive_failures = 0

                while running:
                    with state_lock:
                        if ws_generation != my_generation:
                            return

                    if _typing_signal.is_set():
                        _typing_signal.clear()
                        with state_lock:
                            sid = session_id
                        if sid is not None:
                            try:
                                await websocket.send(json.dumps({"type": "typing", "session_id": sid}))
                            except Exception:
                                pass

                    try:
                        raw = await asyncio.wait_for(websocket.recv(), timeout=1)
                    except asyncio.TimeoutError:
                        # Pas de message reçu récemment : on boucle pour
                        # revérifier `ws_generation` (ex. changement de
                        # salon via /room) et envoyer un éventuel signal
                        # "en train d'écrire" en attente, sans jamais
                        # rester bloqué indéfiniment dans un `recv()`
                        # qui ne reviendra peut-être jamais tout seul.
                        continue

                    data = json.loads(raw)

                    if data.get("type") == "message_created":
                        entry = prepare_incoming(data["envelope"])
                        add_local_message(entry)

                        if screen is not None:
                            draw_chat(screen)

                    elif data.get("type") == "typing_indicator":
                        with state_lock:
                            my_number = own_anonymous_number
                        number = data.get("anonymous_number")
                        if number is not None and number != my_number:
                            name = _format_display_name(number, my_number)
                            show_system_message(f"{name} est en train d'écrire...")
                            if screen is not None:
                                draw_chat(screen)

        except Exception as error:
            if not running:
                return

            with state_lock:
                if ws_generation != my_generation:
                    return

            consecutive_failures += 1

            # Ne jamais échouer en silence : après quelques tentatives,
            # on informe clairement l'utilisateur au lieu de laisser
            # croire que "rien ne se passe". Les messages restent
            # envoyables (POST /messages) même si ce flux temps réel
            # est en panne — voir l'écho local optimiste dans
            # send_text_message/handle_upload.
            if consecutive_failures == 3:
                show_system_message(
                    f"⚠ Flux temps réel indisponible ({error}). "
                    "Les messages envoyés fonctionnent toujours ; "
                    "nouvelle tentative en arrière-plan..."
                )

            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)


def websocket_listener(my_generation: int):
    try:
        asyncio.run(websocket_listener_async(my_generation))
    except Exception:
        pass


# ============================================================
# CURSES — COULEURS, AFFICHAGE
# ============================================================

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_RED, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_WHITE, -1)


def safe_addstr(window, y, x, text, attributes=0):
    height, width = window.getmaxyx()

    if y < 0 or y >= height or x < 0 or x >= width:
        return

    text = str(text)
    available = width - x - 1

    if available <= 0:
        return

    text = text[:available]

    try:
        window.addstr(y, x, text, attributes)
    except curses.error:
        pass


def draw_chat(window, input_text=""):
    with draw_lock:
        height, width = window.getmaxyx()
        window.erase()

        title = " ANONYMOUS "
        title_x = max(0, (width - len(title)) // 2)
        safe_addstr(window, 0, title_x, title, curses.color_pair(1) | curses.A_BOLD)

        with state_lock:
            status = (
                f"{server_url or '(déconnecté)'}  •  salon: {current_room_name or '(aucun)'}"
                f"  •  {('Anonymous #%06d' % own_anonymous_number) if own_anonymous_number else '(pas de session)'}"
            )

        safe_addstr(window, 1, 2, status, curses.color_pair(5))

        with messages_lock:
            current_messages = list(messages)

        message_height = max(1, height - 4)
        visible = current_messages[-message_height:]

        y = 2
        for message in visible:
            if y >= height - 2:
                break

            content = message.get("content", "")

            if message.get("system"):
                safe_addstr(window, y, 2, content, curses.color_pair(4))
            elif message.get("unavailable"):
                safe_addstr(window, y, 2, content, curses.color_pair(3) | curses.A_DIM)
            else:
                prefix = f"{message.get('display_name', 'Anonymous #??????')} : "
                safe_addstr(window, y, 2, prefix, curses.color_pair(1) | curses.A_BOLD)
                safe_addstr(window, y, 2 + len(prefix), content, curses.color_pair(6))

            y += 1

        safe_addstr(window, height - 3, 0, "-" * max(1, width - 1), curses.color_pair(1))
        safe_addstr(window, height - 2, 0, "> ", curses.color_pair(2) | curses.A_BOLD)
        safe_addstr(window, height - 2, 2, input_text, curses.color_pair(6))

        cursor_x = min(width - 1, 2 + len(input_text))
        try:
            window.move(height - 2, cursor_x)
        except curses.error:
            pass

        window.refresh()


# ============================================================
# PSEUDOS LOCAUX (/nick) — jamais envoyés au serveur
# ============================================================

def handle_nick(args: list[str]) -> None:
    if not args:
        if local_nicknames:
            show_system_message("Pseudos locaux définis pour cette session :")
            for number, (name, color) in local_nicknames.items():
                show_system_message(f"  #{number:06d} -> {name} ({color})")
        else:
            show_system_message("Aucun pseudo local défini. Utilisation : /nick <numéro> <nom> [couleur]")
        return

    if len(args) < 2:
        show_system_message("Utilisation : /nick <numéro> <nom> [couleur]")
        show_system_message(f"Couleurs disponibles : {', '.join(NICKNAME_COLORS)}")
        return

    try:
        number = int(args[0].lstrip("#"))
    except ValueError:
        show_system_message("Le numéro doit être celui affiché, ex: /nick 591679 Alice")
        return

    color = args[-1].lower() if len(args) > 2 and args[-1].lower() in NICKNAME_COLORS else "white"
    name_parts = args[1:-1] if len(args) > 2 and args[-1].lower() in NICKNAME_COLORS else args[1:]
    name = " ".join(name_parts)

    local_nicknames[number] = (name, color)
    show_system_message(
        f"Pseudo local défini : #{number:06d} -> {name} ({color}). "
        "Uniquement visible par vous, jamais envoyé au serveur, "
        "et sans effet la prochaine session (le numéro change à chaque connexion)."
    )


# ============================================================
# RÉACTIONS ET RÉPONSES (chiffrées, comme un message normal)
# ============================================================

def handle_react(args: list[str]) -> None:
    if len(args) < 2:
        show_system_message("Utilisation : /react <id_message> <emoji>")
        return

    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    try:
        target_id = int(args[0])
    except ValueError:
        show_system_message("L'id du message doit être un nombre (visible dans l'historique).")
        return

    from crypto import encrypt_message

    payload = ReactionPayload(emoji=args[1], target_id=target_id)
    envelope = encrypt_message(active_keyring, payload.encode(), envelope_type="reaction")

    try:
        response = post_signed_envelope(base_url, envelope)
        add_local_message(prepare_incoming(response.json()))
    except requests.HTTPError as error:
        detail = error.response.text if error.response is not None else str(error)
        show_system_message(f"Réaction refusée : {detail}")


def handle_reply(args: list[str]) -> None:
    if len(args) < 2:
        show_system_message("Utilisation : /reply <id_message> <texte>")
        return

    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    try:
        target_id = int(args[0])
    except ValueError:
        show_system_message("L'id du message doit être un nombre (visible dans l'historique).")
        return

    from crypto import encrypt_message

    text = " ".join(args[1:])
    payload = TextPayload(body=text, reply_to=target_id)
    envelope = encrypt_message(active_keyring, payload.encode())

    try:
        response = post_signed_envelope(base_url, envelope)
        add_local_message(prepare_incoming(response.json()))
    except requests.HTTPError as error:
        detail = error.response.text if error.response is not None else str(error)
        show_system_message(f"Réponse refusée : {detail}")


# ============================================================
# ADMINISTRATION ÉPHÉMÈRE (/admin) — voir docs/crypto.md
# ============================================================

def _admin_request(base_url: str, endpoint: str, extra_fields: dict, *canonical_parts: str) -> dict:
    with state_lock:
        sid = session_id
        identity = signing_identity

    if sid is None or identity is None:
        raise RuntimeError("aucune session active — /connect d'abord.")

    signature = identity.sign(admin_canonical_bytes(*canonical_parts))
    body = {"session_id": sid, "signature": b64e(signature), **extra_fields}

    response = requests.post(
        f"{base_url}/{endpoint}",
        json=body,
        headers=http_headers(),
        timeout=Config["network"]["connect_timeout_seconds"],
    )
    response.raise_for_status()
    return response.json()


def handle_admin(args: list[str]) -> None:
    global is_admin

    with state_lock:
        base_url = server_url

    if base_url is None:
        show_system_message("Aucun serveur connecté.")
        return

    if not args:
        show_system_message("Utilisation : /admin claim|reload|room-password [...]")
        return

    sub = args[0].lower()

    if sub == "claim":
        password = args[1] if len(args) > 1 else None
        try:
            _admin_request(base_url, "admin/claim", {"password": password}, "claim")
            is_admin = True
            show_system_message(
                "Vous êtes désormais administrateur de ce serveur (le savoir "
                "reste local à ce client : personne d'autre n'en est informé)."
            )
        except requests.HTTPError as error:
            detail = error.response.text if error.response is not None else str(error)
            show_system_message(f"Impossible de revendiquer le rôle admin : {detail}")
        return

    if sub == "reload":
        try:
            result = _admin_request(base_url, "admin/reload", {}, "reload")
            sections = result.get("reloaded_sections", [])
            show_system_message(
                f"Configuration rechargée : {', '.join(sections) if sections else '(aucun changement)'}"
            )
        except requests.HTTPError as error:
            detail = error.response.text if error.response is not None else str(error)
            show_system_message(f"Rechargement refusé : {detail}")
        return

    if sub == "room-password":
        if len(args) < 2:
            show_system_message("Utilisation : /admin room-password <salon> [mot_de_passe]")
            return

        room_name = args[1]
        password = args[2] if len(args) > 2 else None

        try:
            result = _admin_request(
                base_url, "admin/rooms/password", {"room": room_name, "password": password},
                "room-password", room_name, password or "",
            )
            show_system_message(
                f"Salon '{room_name}' : mot de passe "
                f"{'défini' if result['has_password'] else 'retiré'} (historique conservé)."
            )
        except requests.HTTPError as error:
            detail = error.response.text if error.response is not None else str(error)
            show_system_message(f"Action refusée : {detail}")
        return

    show_system_message(f"Sous-commande /admin inconnue : {sub}")


# ============================================================
# COMMANDES
# ============================================================

def handle_command(command: str) -> bool:
    parts = command.split(" ")
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd == "/help":
        show_system_message("/connect URL [password]   se connecter à un serveur")
        show_system_message("/disconnect               se déconnecter")
        show_system_message("/server                   afficher l'état de connexion")
        show_system_message("/room new|join|use|list|password    gérer les salons")
        show_system_message("/room exchange start|respond|finish   échange X25519")
        show_system_message("/upload chemin            envoyer un fichier chiffré")
        show_system_message("/download id              télécharger un fichier reçu")
        show_system_message("/react id emoji           réagir à un message")
        show_system_message("/reply id texte           répondre à un message")
        show_system_message("/nick numéro nom [couleur]  pseudo local (jamais envoyé)")
        show_system_message("/admin claim|reload|room-password   administration éphémère")
        show_system_message("/quit                     quitter")
        show_system_message("texte + Entrée            envoyer un message")
        return False

    if cmd in ("/quit", "/exit"):
        return True

    if cmd == "/connect":
        handle_connect(args)
        return False

    if cmd == "/disconnect":
        handle_disconnect()
        return False

    if cmd == "/server":
        with state_lock:
            show_system_message(f"Serveur : {server_url or '(aucun)'}")
            show_system_message(f"Salon actif : {current_room_name or '(aucun)'}")
            show_system_message(f"Authentifié : {'oui' if auth_token else 'non'}")
            show_system_message(
                "Identité de session : "
                + (f"Anonymous #{own_anonymous_number:06d}" if own_anonymous_number else "(aucune)")
            )
            show_system_message(f"Administrateur (local uniquement) : {'oui' if is_admin else 'non'}")
        return False

    if cmd == "/room":
        handle_room(args)
        return False

    if cmd == "/upload":
        if not args:
            show_system_message("Utilisation : /upload chemin_du_fichier")
        else:
            handle_upload(" ".join(args))
        return False

    if cmd == "/download":
        if not args:
            show_system_message("Utilisation : /download id_fichier")
        else:
            handle_download(args[0])
        return False

    if cmd == "/react":
        handle_react(args)
        return False

    if cmd == "/reply":
        handle_reply(args)
        return False

    if cmd == "/nick":
        handle_nick(args)
        return False

    if cmd == "/admin":
        handle_admin(args)
        return False

    if cmd.startswith("/"):
        show_system_message(f"Commande inconnue : {cmd}. Utilisez /help.")
        return False

    return False


# ============================================================
# BOUCLE DE SAISIE
# ============================================================

def input_loop(window):
    global running

    input_text = ""
    window.keypad(True)
    window.nodelay(False)

    while running:
        draw_chat(window, input_text)

        key = window.getch()

        if key in (curses.KEY_ENTER, 10, 13):
            text = input_text.strip()
            input_text = ""

            if not text:
                continue

            if text.startswith("/"):
                if handle_command(text):
                    running = False
                    break
            else:
                try:
                    send_text_message(text)
                except requests.HTTPError as error:
                    detail = error.response.text if error.response is not None else str(error)
                    show_system_message(f"Erreur serveur : {detail}")
                except Exception as error:
                    show_system_message(f"Erreur : {error}")

        elif key in (curses.KEY_BACKSPACE, 127, 8):
            input_text = input_text[:-1]

        elif 32 <= key <= 126:
            was_empty = not input_text
            input_text += chr(key)
            if was_empty:
                # Signal "en train d'écrire" — uniquement au début
                # d'une saisie, pas à chaque touche (voir
                # websocket_listener_async, qui l'envoie au prochain
                # passage de sa boucle, sous 1 seconde).
                _typing_signal.set()


def run_chat(window):
    global screen, running

    screen = window
    running = True

    curses.curs_set(1)
    init_colors()

    show_system_message("Bienvenue sur Anonymous.")
    show_system_message(
        "Aucun message ne sera lisible par le serveur : chiffrement de bout en bout."
    )
    show_system_message(
        "Chaque connexion vous attribue un numéro temporaire (Anonymous #XXXXXX), "
        "jamais un compte : il change à chaque /connect."
    )
    show_system_message("/connect URL puis /room new (ou /room join <invite>) pour commencer.")
    show_system_message("/help pour la liste des commandes.")

    try:
        input_loop(window)
    finally:
        running = False


def main():
    try:
        curses.wrapper(run_chat)
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()
