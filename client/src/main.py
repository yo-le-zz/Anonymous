import asyncio
import curses
import json
import locale
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
NICKNAME_COLOR_PAIRS = {"cyan": 1, "green": 2, "red": 3, "yellow": 4, "magenta": 5, "white": 6}

# Réactions agrégées par message ciblé : {id_message: {emoji: nombre}}.
# Une réaction n'est JAMAIS affichée comme une ligne de discussion à
# part entière — elle est ajoutée en petit à côté du message ciblé
# (voir draw_chat), pour éviter que le fil de discussion ne se
# remplisse de lignes "😀 en réaction à #12".
reactions_by_target: dict[int, dict[str, int]] = {}
reactions_lock = threading.Lock()

EMOJI_PRESETS = [
    ("👍", "pouce en l'air"),
    ("👎", "pouce en bas"),
    ("😂", "rire"),
    ("❤️", "cœur"),
    ("😮", "surprise"),
    ("😢", "triste"),
    ("🎉", "fête"),
    ("🔥", "feu"),
]

# Suggestions de commandes affichées au-dessus de la zone de saisie
# dès que le texte tapé commence par "/" (voir draw_chat) : nom,
# gabarit d'arguments (placeholder), description courte.
COMMAND_HELP = [
    ("/connect", "<url> [mot_de_passe]", "se connecter à un serveur"),
    ("/disconnect", "", "se déconnecter"),
    ("/server", "", "état de connexion"),
    ("/join", "<salon> [mot_de_passe]", "rejoindre/créer un salon simple"),
    ("/room", "new|join|use|leave|list|password ...", "gérer les salons (avancé)"),
    ("/upload", "<chemin>", "envoyer un fichier chiffré"),
    ("/download", "[id]", "télécharger un fichier (dernier par défaut)"),
    ("/react", "[numéro|emoji] [id]", "réagir (dernier message par défaut)"),
    ("/reply", "[id] <texte>", "répondre (dernier message par défaut)"),
    ("/nick", "<numéro> <nom> [couleur]", "pseudo local"),
    ("/admin", "claim|reload|room-password ...", "administration éphémère"),
    ("/help", "", "liste des commandes"),
    ("/quit", "", "quitter"),
]

# Indicateurs "en train d'écrire" (voir docs/crypto.md) : numéro ->
# horodatage local (monotonic) de la dernière confirmation reçue.
# Purgé après quelques secondes sans nouvelle confirmation (voir
# draw_chat / websocket_listener_async), jamais persisté.
typing_users: dict[int, float] = {}
typing_lock = threading.Lock()
TYPING_EXPIRY_SECONDS = 6

# Signal (thread-safe) qu'un indicateur "en train d'écrire" doit être
# envoyé/arrêté au prochain passage de la boucle WebSocket — voir
# input_loop() et websocket_listener_async().
_typing_signal = threading.Event()
_typing_stop_signal = threading.Event()
_own_typing_active = False
_own_last_typing_sent = 0.0

ws_generation = 0  # incrémenté à chaque /connect ou /disconnect pour
                   # invalider proprement le thread WebSocket précédent

# ------------------------------------------------------------------
# Historique local de saisie (flèches haut/bas) — purement un confort
# d'UI, JAMAIS envoyé au serveur ni persisté entre sessions : juste la
# liste des commandes/messages déjà tapés pendant cette connexion-ci.
# ------------------------------------------------------------------
input_history: list[str] = []
MAX_INPUT_HISTORY = 200
# None = pas en train de naviguer l'historique (saisie libre). Un
# entier est l'index dans `input_history` (0 = le plus ancien montré,
# len(input_history) = "au-delà du plus récent", c.-à-d. retour au
# brouillon en cours via _history_draft).
_history_index: int | None = None
# Ce que l'utilisateur était en train de taper AVANT d'appuyer sur
# flèche haut pour la première fois — restauré si on redescend
# au-delà du message le plus récent de l'historique (comme un shell).
_history_draft: str = ""


def _remember_input(text: str) -> None:
    """Ajoute `text` à l'historique local, sauf doublon consécutif
    immédiat (spam du même message/commande), et plafonne la taille."""

    global input_history
    if not text:
        return
    if input_history and input_history[-1] == text:
        return
    input_history.append(text)
    if len(input_history) > MAX_INPUT_HISTORY:
        input_history = input_history[-MAX_INPUT_HISTORY:]


def _maybe_send_typing(input_text: str) -> None:
    """Appelée à chaque caractère tapé. N'envoie un signal "en train
    d'écrire" que pour un VRAI message (jamais pour une commande "/"),
    et seulement toutes les ~3 secondes tant que la saisie continue —
    pas à chaque touche, pour ne pas surcharger le salon."""

    global _own_typing_active, _own_last_typing_sent

    composing_message = bool(input_text) and not input_text.startswith("/")
    now = time.monotonic()

    if composing_message:
        if not _own_typing_active or (now - _own_last_typing_sent) > 3:
            _own_typing_active = True
            _own_last_typing_sent = now
            _typing_stop_signal.clear()
            _typing_signal.set()
    else:
        _send_stopped_typing()


def _send_stopped_typing() -> None:
    global _own_typing_active

    if _own_typing_active:
        _own_typing_active = False
        _typing_signal.clear()
        _typing_stop_signal.set()


_current_input_buffer = ""
_current_input_buffer_lock = threading.Lock()


def _current_input_text() -> str:
    with _current_input_buffer_lock:
        return _current_input_buffer


def _set_current_input_text(text: str) -> None:
    global _current_input_buffer
    with _current_input_buffer_lock:
        _current_input_buffer = text


def _prune_stale_typing() -> bool:
    """Purge les indicateurs "en train d'écrire" trop anciens (au cas
    où un signal d'arrêt aurait été perdu, ex. déconnexion brutale).
    Retourne True si l'affichage doit être rafraîchi."""

    now = time.monotonic()
    removed = False

    with typing_lock:
        stale = [number for number, seen_at in typing_users.items() if now - seen_at > TYPING_EXPIRY_SECONDS]
        for number in stale:
            del typing_users[number]
            removed = True

    return removed


# ============================================================
# UTILITAIRES D'ÉTAT
# ============================================================

def _leave_current_room() -> None:
    """Quitte le salon actif sans se déconnecter du serveur : repasse
    en état "aucun salon actif" (voir prepare_incoming, qui affiche
    alors '[aucun salon actif...]' pour tout message reçu entre temps).
    Bascule `ws_generation` comme set_room() pour invalider proprement
    le thread WebSocket abonné à l'ancien salon — sans ça, il resterait
    abonné à un salon qu'on vient pourtant de quitter."""

    global current_room_name, current_room, keyring, ws_generation

    with state_lock:
        current_room_name = None
        current_room = None
        keyring = None
        ws_generation += 1

    with messages_lock:
        messages.clear()
    with reactions_lock:
        reactions_by_target.clear()
    with _seen_reaction_ids_lock:
        _seen_reaction_ids.clear()


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
        # Numéro affiché à l'utilisateur ("#N"), propre à CHAQUE salon
        # (pas un id global) — voir ROOM_SEQ_TYPES côté serveur. None
        # pour tout ce qui n'en consomme pas (réactions notamment) :
        # elles ne doivent jamais apparaître comme une ligne numérotée.
        "room_seq": envelope_dict.get("room_seq"),
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
            entry["reaction_emoji"] = reaction.emoji
            entry["reaction_target_id"] = reaction.target_id
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
            # On n'affiche plus le file_id brut (UUID illisible, jamais
            # utile à l'utilisateur) : /download tout court (dernier
            # fichier) ou /download #N (ce numéro, via room_seq) suffit.
            entry["content"] = f"[{kind}] {meta.filename} ({meta.size_bytes} octets) — /download"
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


_seen_reaction_ids: set[int] = set()
_seen_reaction_ids_lock = threading.Lock()


def add_local_message(entry: dict) -> None:
    if entry.get("is_reaction") and not entry.get("unavailable"):
        # Une réaction n'occupe jamais sa propre ligne de discussion :
        # elle est agrégée sur le message ciblé (voir draw_chat). On
        # déduplique par id d'enveloppe (écho local + diffusion WS
        # peuvent toutes les deux livrer la même réaction).
        message_id = entry.get("id")
        with _seen_reaction_ids_lock:
            if message_id is not None:
                if message_id in _seen_reaction_ids:
                    return
                _seen_reaction_ids.add(message_id)

        # `reaction_target_id` est le numéro que l'émetteur a tapé
        # (/react <emoji> <N>) ou celui par défaut (_last_room_seq()) :
        # c'est donc déjà un numéro de salon (`room_seq`), pas un id
        # global — `reactions_by_target` est keyé pareil, voir draw_chat.
        target_room_seq = entry.get("reaction_target_id")
        emoji = entry.get("reaction_emoji")

        if target_room_seq is not None and emoji:
            with reactions_lock:
                counts = reactions_by_target.setdefault(target_room_seq, {})
                counts[emoji] = counts.get(emoji, 0) + 1
        return

    with messages_lock:
        for existing in messages:
            if existing.get("id") == entry.get("id") and entry.get("id") is not None:
                return
        messages.append(entry)


def _last_room_seq() -> int | None:
    """Numéro de salon (`#N`, propre au salon courant — PAS un id
    global) du dernier vrai message reçu (ni système, ni réaction —
    celles-ci n'apparaissent plus comme des lignes à part entière).
    Utilisé pour que /react et /reply fonctionnent SANS que
    l'utilisateur ait à chercher/compter un numéro à la main."""

    with messages_lock:
        for entry in reversed(messages):
            if entry.get("room_seq") is not None and not entry.get("system"):
                return entry["room_seq"]
    return None


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

        # Bug réel découvert pendant le scan : `room_seq` repart de 1
        # dans CHAQUE salon (voir docs/crypto.md) — sans vider l'état
        # de réactions ici, une réaction agrégée sur le message #3 du
        # salon précédent continuait de s'afficher par erreur sur le
        # message #3 du nouveau salon (même numéro, salon différent).
        with messages_lock:
            messages.clear()
        with reactions_lock:
            reactions_by_target.clear()
        with _seen_reaction_ids_lock:
            _seen_reaction_ids.clear()

        # Second bug réel découvert pendant le scan : l'historique
        # était jusqu'ici ajouté DIRECTEMENT à `messages` (extend), ce
        # qui contournait complètement `add_local_message` — une
        # réaction présente dans l'historique (reconnexion, /room use
        # puis retour) s'affichait donc comme sa PROPRE ligne de
        # discussion ("👍 en réaction à #3") au lieu d'être agrégée
        # à côté du message ciblé. En repassant par
        # `add_local_message`, l'historique suit exactement le même
        # chemin que les messages reçus en direct.
        for entry in prepared:
            add_local_message(entry)

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

def handle_join(args: list[str]) -> None:
    """Rejoint/crée un salon "simple" par nom (+ mot de passe optionnel
    du salon), SANS partage d'invitation hors bande — voir
    crypto.Room.simple() pour la limite de confidentialité que cela
    implique (le serveur peut recalculer le même secret, contrairement
    à /room new). Pratique pour un salon de groupe classique ; utilisez
    /room new si vous avez besoin d'une confidentialité garantie même
    contre le serveur."""

    if not args:
        show_system_message("Utilisation : /join <salon> [mot_de_passe]")
        return

    with state_lock:
        base_url = server_url

    if base_url is None:
        show_system_message("Aucun serveur connecté. /connect d'abord.")
        return

    name = args[0]
    password = " ".join(args[1:]) if len(args) > 1 else None

    try:
        response = requests.get(
            f"{base_url}/rooms", headers=http_headers(),
            timeout=Config["network"]["connect_timeout_seconds"],
        )
        response.raise_for_status()
        rooms_payload = response.json()
    except requests.RequestException as error:
        show_system_message(f"Impossible de contacter le serveur : {error}")
        return

    existing = None
    if rooms_payload.get("enabled", True):
        existing = next((r for r in rooms_payload.get("rooms", []) if r["name"] == name), None)

    if existing and existing["has_password"] and not password:
        show_system_message(f"Le salon '{name}' est protégé : /join {name} <mot_de_passe>")
        return

    if existing is not None and not existing["has_password"] and password:
        show_system_message(
            f"Le salon '{name}' est public (pas de mot de passe) — "
            "le mot de passe fourni sera ignoré pour la vérification serveur, "
            "mais changerait le secret de déchiffrement : ne le précisez pas."
        )
        return

    room = Room.simple(name, password)
    store.save_room(name, room, server_password=password)
    set_room(name, room)

    show_system_message(f"Salon '{name}' rejoint. Empreinte : {room.fingerprint()}")
    show_system_message(
        "⚠ Salon \"simple\" : le secret de chiffrement dérive du nom"
        + ("+mot de passe" if password else "")
        + ". Un serveur qui les connaît pourrait déchiffrer — voir docs/crypto.md §13. "
        "Pour une confidentialité garantie même contre le serveur : /room new."
    )

    if existing is None:
        try:
            requests.post(
                f"{base_url}/rooms", json={"name": name, "password": password},
                headers=http_headers(), timeout=Config["network"]["connect_timeout_seconds"],
            )
        except requests.RequestException:
            pass  # le salon sera de toute façon auto-créé au premier message si autorisé

    fetch_history()


def handle_room(args: list[str]) -> None:
    if not args:
        show_system_message(
            "Utilisation : /room new|join|use|leave|list|password|exchange [...]"
        )
        return

    sub = args[0].lower()

    if sub == "leave":
        with state_lock:
            was_in_room = current_room_name

        if was_in_room is None:
            show_system_message("Aucun salon actif.")
            return

        _leave_current_room()
        show_system_message(f"Salon '{was_in_room}' quitté.")
        return

    # /room new et /room join sont désormais de simples alias de /join
    # (voir handle_join) : un salon se crée ou se rejoint par
    # <nom> [mot_de_passe], sans invitation à partager hors bande. Plus
    # simple à utiliser, au prix de la limite de confidentialité
    # documentée dans docs/crypto.md §13 (le serveur connaît le nom et
    # le mot de passe, et pourrait donc recalculer le même secret) —
    # pour une confidentialité garantie même contre le serveur, utilisez
    # /room exchange à la place.
    if sub in ("new", "join"):
        if len(args) < 2:
            show_system_message(f"Utilisation : /room {sub} <nom> [mot_de_passe]")
            return

        handle_join(args[1:])
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
                "Pour rejoindre : /room join <nom> [mot_de_passe], ou /room use <nom> "
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


def _human_size(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ("o", "Ko", "Mo", "Go"):
        if value < 1024 or unit == "Go":
            return f"{value:.0f} {unit}" if unit == "o" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} Go"


def _last_file_id() -> str | None:
    with messages_lock:
        for entry in reversed(messages):
            if entry.get("file_meta"):
                try:
                    return FileMetadataPayload.decode(entry["file_meta"].encode("utf-8")).file_id
                except Exception:
                    continue
    return None


def _resolve_file_id_from_room_seq(reference: str) -> str | None:
    """`/download 7` est bien plus pratique que de recopier un file_id
    (UUID long et jamais affiché nulle part côté UI) : si `reference`
    est un nombre, on cherche le message-fichier portant ce `room_seq`
    (le même `#N` que celui affiché devant le message dans le salon).
    Retourne None si ce n'est pas un nombre ou si aucun fichier ne
    correspond — l'appelant retombe alors sur `reference` tel quel
    (compatibilité ascendante avec un vrai file_id collé à la main)."""

    candidate = reference.lstrip("#")
    if not candidate.isdigit():
        return None

    target_seq = int(candidate)
    with messages_lock:
        for entry in messages:
            if entry.get("room_seq") == target_seq and entry.get("file_meta"):
                try:
                    return FileMetadataPayload.decode(entry["file_meta"].encode("utf-8")).file_id
                except Exception:
                    return None
    return None


def handle_download(file_id: str | None = None) -> None:
    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    if file_id is None:
        file_id = _last_file_id()
        if file_id is None:
            show_system_message("Aucun fichier reçu pour l'instant.")
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

    # Prévisualisation avant de télécharger quoi que ce soit.
    show_system_message(
        f"Fichier : {meta_json.filename} — {_human_size(meta_json.size_bytes)} "
        f"— {meta_json.mime_type or 'type inconnu'}"
    )

    default_destination = str(store.downloads_dir / meta_json.filename)
    destination_str = _prompt_line("Enregistrer sous", default_destination)
    destination = Path(destination_str).expanduser()

    if destination.exists():
        confirm = _prompt_line(f"'{destination}' existe déjà, écraser ? (o/N)", "n")
        if confirm.strip().lower() not in ("o", "oui", "y", "yes"):
            show_system_message("Téléchargement annulé.")
            return

    destination.parent.mkdir(parents=True, exist_ok=True)

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
                                await websocket.send(
                                    json.dumps({"type": "typing", "session_id": sid, "active": True})
                                )
                            except Exception:
                                pass

                    if _typing_stop_signal.is_set():
                        _typing_stop_signal.clear()
                        with state_lock:
                            sid = session_id
                        if sid is not None:
                            try:
                                await websocket.send(
                                    json.dumps({"type": "typing", "session_id": sid, "active": False})
                                )
                            except Exception:
                                pass

                    try:
                        raw = await asyncio.wait_for(websocket.recv(), timeout=1)
                    except asyncio.TimeoutError:
                        # Pas de message reçu récemment : on boucle pour
                        # revérifier `ws_generation` (ex. changement de
                        # salon via /room), envoyer un éventuel signal
                        # "en train d'écrire" en attente, et purger les
                        # indicateurs de frappe devenus obsolètes (voir
                        # _prune_stale_typing) sans jamais rester bloqué
                        # indéfiniment dans un `recv()` qui ne reviendra
                        # peut-être jamais tout seul.
                        if _prune_stale_typing() and screen is not None:
                            draw_chat(screen, _current_input_text())
                        continue

                    data = json.loads(raw)

                    if data.get("type") == "message_created":
                        entry = prepare_incoming(data["envelope"])
                        add_local_message(entry)

                        if screen is not None:
                            draw_chat(screen, _current_input_text())

                    elif data.get("type") == "typing_indicator":
                        with state_lock:
                            my_number = own_anonymous_number
                        number = data.get("anonymous_number")
                        active = data.get("active", True)

                        if number is not None and number != my_number:
                            with typing_lock:
                                if active:
                                    typing_users[number] = time.monotonic()
                                else:
                                    typing_users.pop(number, None)

                            if screen is not None:
                                draw_chat(screen, _current_input_text())

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


def _prompt_line(prompt_text: str, default: str = "") -> str:
    """Bloque brièvement pour demander une valeur à l'utilisateur sur
    la ligne de saisie (ex. chemin de destination d'un téléchargement).
    Gère correctement les caractères Unicode (accents...) via
    `get_wch()`. Entrée vide -> retourne `default`. Doit être appelé
    depuis le thread principal (curses), jamais depuis un thread
    d'arrière-plan."""

    if screen is None:
        return default

    height, width = screen.getmaxyx()
    full_prompt = f"{prompt_text} [{default}] : " if default else f"{prompt_text} : "
    text = ""

    curses.curs_set(1)
    try:
        while True:
            safe_addstr(screen, height - 1, 0, " " * (width - 1))
            safe_addstr(screen, height - 1, 0, full_prompt, curses.color_pair(2) | curses.A_BOLD)
            safe_addstr(screen, height - 1, min(width - 2, len(full_prompt)), text, curses.color_pair(6))
            screen.refresh()

            try:
                key = screen.get_wch()
            except curses.error:
                continue

            # Même bug que celui corrigé dans input_loop (voir plus
            # bas) : `get_wch()` peut livrer Entrée/Backspace comme un
            # entier SPÉCIAL (curses.KEY_ENTER...) OU comme la CHAÎNE
            # "\n"/"\r"/"\x7f" selon le terminal. Ce prompt ne testait
            # Entrée que dans le cas entier — sur un terminal livrant
            # la chaîne, taper un chemin et appuyer sur Entrée ne
            # faisait RIEN (bug réel observé : impossible de valider
            # un chemin de destination personnalisé). Détecté
            # indépendamment du type, comme dans input_loop.
            is_enter = key in (curses.KEY_ENTER, 10, 13, "\n", "\r")
            is_backspace = key in (curses.KEY_BACKSPACE, 127, 8, "\x7f", "\b")

            if is_enter:
                return text.strip() or default
            if is_backspace:
                text = text[:-1]
            elif key == 27:  # Échap : annule, garde le défaut
                return default
            elif isinstance(key, str) and key.isprintable():
                text += key
    finally:
        curses.curs_set(0)


def _typing_status_text() -> str:
    _prune_stale_typing()

    with state_lock:
        my_number = own_anonymous_number

    with typing_lock:
        numbers = [n for n in typing_users if n != my_number]

    if not numbers:
        return ""

    if len(numbers) > 2:
        return "Plusieurs personnes sont en train d'écrire..."

    names = [_format_display_name(n, my_number) for n in numbers]

    if len(names) == 1:
        return f"{names[0]} est en train d'écrire..."

    return f"{names[0]} et {names[1]} sont en train d'écrire..."


def _matching_commands(input_text: str) -> list[tuple[str, str, str]]:
    if not input_text.startswith("/"):
        return []

    parts = input_text.split(" ", 1)
    typed_command = parts[0].lower()
    has_args_started = len(parts) > 1

    if has_args_started:
        # La commande est déjà choisie : un seul rappel de son gabarit
        # d'arguments, pas une liste de correspondances.
        match = next((c for c in COMMAND_HELP if c[0] == typed_command), None)
        return [match] if match else []

    return [c for c in COMMAND_HELP if c[0].startswith(typed_command)][:5]


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

        # Zone réservée en bas, AU-DESSUS de la ligne de saisie, pour :
        # - les suggestions de commande (jusqu'à 5 lignes, seulement
        #   pendant la frappe d'une commande) ;
        # - l'indicateur "en train d'écrire" (1 ligne, façon Discord).
        # Dimensionnée dynamiquement pour ne pas gâcher de place quand
        # rien n'est affiché.
        suggestions = _matching_commands(input_text)
        typing_text = _typing_status_text()

        reserved_bottom = 2  # séparateur + ligne de saisie
        if typing_text:
            reserved_bottom += 1
        if suggestions:
            reserved_bottom += len(suggestions)

        with messages_lock:
            current_messages = list(messages)

        message_height = max(1, height - 2 - reserved_bottom)
        visible = current_messages[-message_height:]

        # Regroupe les lignes indisponibles/système consécutives et
        # identiques (ex. plusieurs messages non déchiffrables d'affilée)
        # en une seule ligne "(×N)", plutôt que de répéter N fois le
        # même texte à l'écran.
        collapsed: list[tuple[dict, int]] = []
        for message in visible:
            if (
                collapsed
                and message.get("unavailable")
                and collapsed[-1][0].get("unavailable")
                and collapsed[-1][0].get("content") == message.get("content")
            ):
                previous_message, count = collapsed[-1]
                collapsed[-1] = (previous_message, count + 1)
            else:
                collapsed.append((message, 1))

        y = 2
        for message, repeat_count in collapsed:
            if y >= height - reserved_bottom:
                break

            content = message.get("content", "")
            if repeat_count > 1:
                content = f"{content}  (×{repeat_count})"

            if message.get("system"):
                safe_addstr(window, y, 2, content, curses.color_pair(4))
            elif message.get("unavailable"):
                safe_addstr(window, y, 2, content, curses.color_pair(3) | curses.A_DIM)
            else:
                # Numéro affiché et utilisé pour /react, /reply,
                # /download <N> : propre au salon courant (room_seq),
                # PAS l'id global en base — voir docs/crypto.md.
                room_seq = message.get("room_seq")
                id_prefix = f"#{room_seq} " if room_seq is not None else ""
                safe_addstr(window, y, 2, id_prefix, curses.A_DIM)

                number = message.get("anonymous_number")
                nickname_entry = local_nicknames.get(number) if number is not None else None
                color_pair_number = NICKNAME_COLOR_PAIRS.get(nickname_entry[1], 1) if nickname_entry else 1

                prefix = f"{message.get('display_name', 'Anonymous #??????')} : "
                x = 2 + len(id_prefix)
                safe_addstr(window, y, x, prefix, curses.color_pair(color_pair_number) | curses.A_BOLD)

                full_content = content
                if room_seq is not None:
                    with reactions_lock:
                        target_reactions = reactions_by_target.get(room_seq)
                    if target_reactions:
                        summary = " ".join(f"{emoji}×{n}" for emoji, n in target_reactions.items())
                        full_content = f"{content}  {summary}"

                safe_addstr(window, y, x + len(prefix), full_content, curses.color_pair(6))

            y += 1

        bottom_y = height - reserved_bottom

        for offset, (name, placeholder, description) in enumerate(suggestions):
            line = f"{name} {placeholder}" if placeholder else name
            safe_addstr(window, bottom_y + offset, 2, f"{line}  — {description}", curses.color_pair(2) | curses.A_DIM)

        if typing_text:
            safe_addstr(
                window, bottom_y + len(suggestions), 2, typing_text,
                curses.color_pair(5) | curses.A_ITALIC if hasattr(curses, "A_ITALIC") else curses.color_pair(5),
            )

        safe_addstr(window, height - 2, 0, "-" * max(1, width - 1), curses.color_pair(1))
        safe_addstr(window, height - 1, 0, "> ", curses.color_pair(2) | curses.A_BOLD)
        safe_addstr(window, height - 1, 2, input_text, curses.color_pair(6))

        cursor_x = min(width - 1, 2 + len(input_text))
        try:
            window.move(height - 1, cursor_x)
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
    if not args:
        show_system_message(
            "Réactions rapides : /react <numéro> [id]  (id omis = dernier message)"
        )
        for index, (emoji, label) in enumerate(EMOJI_PRESETS, start=1):
            show_system_message(f"  {index}. {emoji}  {label}")
        show_system_message("Ou directement un emoji : /react 😀 [id]")
        return

    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    first = args[0]

    if first.isdigit() and 1 <= int(first) <= len(EMOJI_PRESETS):
        emoji = EMOJI_PRESETS[int(first) - 1][0]
    else:
        emoji = first

    target_id = None
    if len(args) > 1:
        candidate = args[1].lstrip("#")
        if candidate.isdigit():
            target_id = int(candidate)

    if target_id is None:
        target_id = _last_room_seq()

    if target_id is None:
        show_system_message("Aucun message disponible auquel réagir pour l'instant.")
        return

    from crypto import encrypt_message

    payload = ReactionPayload(emoji=emoji, target_id=target_id)
    envelope = encrypt_message(active_keyring, payload.encode(), envelope_type="reaction")

    try:
        response = post_signed_envelope(base_url, envelope)
        add_local_message(prepare_incoming(response.json()))
    except requests.HTTPError as error:
        detail = error.response.text if error.response is not None else str(error)
        show_system_message(f"Réaction refusée : {detail}")


def handle_reply(args: list[str]) -> None:
    if not args:
        show_system_message("Utilisation : /reply [id] <texte>  (id omis = dernier message)")
        return

    with state_lock:
        active_keyring = keyring
        base_url = server_url

    if base_url is None or active_keyring is None:
        show_system_message("Aucun serveur/salon actif.")
        return

    target_id = None
    text_args = args

    first_candidate = args[0].lstrip("#")
    if first_candidate.isdigit() and len(args) > 1:
        target_id = int(first_candidate)
        text_args = args[1:]

    if target_id is None:
        target_id = _last_room_seq()

    if target_id is None:
        show_system_message("Aucun message disponible auquel répondre pour l'instant.")
        return

    if not text_args:
        show_system_message("Utilisation : /reply [id] <texte>")
        return

    from crypto import encrypt_message

    text = " ".join(text_args)
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
        show_system_message("/join salon [mot_de_passe]  rejoindre/créer un salon simple")
        show_system_message("/room new|join|use|list|password    salons avancés (E2EE garantie)")
        show_system_message("/room exchange start|respond|finish   échange X25519")
        show_system_message("/upload chemin            envoyer un fichier chiffré")
        show_system_message("/download [id]            télécharger un fichier (dernier par défaut)")
        show_system_message("/react [numéro|emoji] [id]   réagir (dernier message par défaut)")
        show_system_message("/reply [id] texte         répondre (dernier message par défaut)")
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

    if cmd == "/join":
        handle_join(args)
        return False

    if cmd == "/upload":
        if not args:
            show_system_message("Utilisation : /upload chemin_du_fichier")
        else:
            handle_upload(" ".join(args))
        return False

    if cmd == "/download":
        # Accepte : aucun argument (dernier fichier reçu), un numéro
        # #N (room_seq, celui affiché devant le message), ou un
        # file_id brut collé à la main (compatibilité ascendante).
        reference = args[0] if args else None
        if reference is not None:
            resolved = _resolve_file_id_from_room_seq(reference)
            if resolved is not None:
                reference = resolved
        handle_download(reference)
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
    global running, _history_index, _history_draft

    input_text = ""
    window.keypad(True)
    window.nodelay(False)

    while running:
        draw_chat(window, input_text)

        try:
            key = window.get_wch()
        except curses.error:
            continue

        # `get_wch()` retourne soit un entier (touches spéciales,
        # flèches, Backspace...), soit une chaîne d'UN caractère
        # Unicode (lettres, accents, emoji...) — contrairement à
        # `getch()` qui ne gère que l'ASCII 0-255 et cassait toute
        # saisie contenant des accents ou des emoji.
        #
        # IMPORTANT : Entrée peut être livrée SOIT comme entier
        # (curses.KEY_ENTER) SOIT comme la chaîne "\n"/"\r" selon le
        # terminal — il faut donc la détecter AVANT de trier sur le
        # type, sans quoi "\n" tombe dans la branche "texte", n'est
        # pas imprimable, et Entrée ne fait plus rien du tout (bug
        # réel observé : plus aucun message ni commande ne partait).
        # 27 (ESC) est inclus car certains terminaux / claviers (pavé
        # numérique sur certains émulateurs) livrent Entrée comme ESC
        # dans de rares configurations — fix remonté par l'utilisateur
        # lui-même après un cas réel observé.
        is_enter = key in (curses.KEY_ENTER, 10, 13, 27, "\n", "\r")
        is_backspace = key in (curses.KEY_BACKSPACE, 127, 8, "\x7f", "\b")

        if is_enter:
            text = input_text.strip()
            input_text = ""
            _history_index = None
            _history_draft = ""
            _set_current_input_text(input_text)
            _send_stopped_typing()

            if not text:
                continue

            _remember_input(text)

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

        elif is_backspace:
            input_text = input_text[:-1]
            _history_index = None  # on édite -> on quitte la navigation
            _set_current_input_text(input_text)
            if not input_text:
                _send_stopped_typing()

        elif key in (curses.KEY_UP, curses.KEY_DOWN):
            # Rappel local des saisies précédentes (commandes ET
            # messages), comme un shell — jamais envoyé au serveur, ne
            # fonctionne que pour cette connexion (voir input_history).
            if not input_history:
                continue

            if key == curses.KEY_UP:
                if _history_index is None:
                    # Première pression : on mémorise ce qui était en
                    # cours de frappe pour pouvoir y revenir en
                    # redescendant au-delà du message le plus récent.
                    _history_draft = input_text
                    _history_index = len(input_history) - 1
                elif _history_index > 0:
                    _history_index -= 1
                input_text = input_history[_history_index]
            else:  # KEY_DOWN
                if _history_index is None:
                    continue
                if _history_index < len(input_history) - 1:
                    _history_index += 1
                    input_text = input_history[_history_index]
                else:
                    # Au-delà du plus récent : retour au brouillon.
                    _history_index = None
                    input_text = _history_draft

            _set_current_input_text(input_text)

        elif key in (9, "\t"):
            # Tab : complète avec la PREMIÈRE commande proposée (celle
            # affichée en tête de la liste de suggestions au-dessus de
            # la ligne de saisie — voir _matching_commands/draw_chat).
            # Seulement tant que le nom de la commande est en cours de
            # frappe (pas d'espace encore) : une fois les arguments
            # commencés, il n'y a rien à compléter.
            if " " not in input_text:
                suggestions = _matching_commands(input_text)
                if suggestions:
                    input_text = suggestions[0][0] + " "
                    _history_index = None
                    _set_current_input_text(input_text)
                    _maybe_send_typing(input_text)

        elif isinstance(key, str) and key.isprintable():
            input_text += key
            _history_index = None  # on édite -> on quitte la navigation
            _set_current_input_text(input_text)
            _maybe_send_typing(input_text)


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
    # Indispensable pour que curses gère correctement les caractères
    # Unicode (accents, emoji...) en entrée ET en affichage — sans
    # ceci, Python/curses reste bloqué en locale "C" (ASCII strict) et
    # toute touche accentuée ou tout emoji est silencieusement perdu.
    # Sur certains systèmes (conteneurs minimalistes, Windows sans
    # locale UTF-8 installée...) la locale par défaut de l'utilisateur
    # ("") n'existe pas et lève locale.Error. On retente alors avec
    # "C.UTF-8" (toujours UTF-8, toujours disponible sur les systèmes
    # récents) puis, en dernier recours, on continue sans bloquer :
    # l'affichage restera correct dans la plupart des cas, seule la
    # saisie de caractères très exotiques pourrait être affectée.
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        try:
            locale.setlocale(locale.LC_ALL, "C.UTF-8")
        except locale.Error:
            pass

    try:
        curses.wrapper(run_chat)
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()
