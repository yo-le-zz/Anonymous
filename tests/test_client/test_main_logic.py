"""Tests de la logique ajoutée en v1.0.5 côté client : salons "simples"
(/join), agrégation des réactions, valeurs par défaut de /react et
/reply, indicateur de frappe agrégé, utilitaires d'affichage.

Isolation sys.path / sys.modules : voir tests/test_client/test_crypto.py
et tests/test_server/test_server.py — même principe ici."""

from __future__ import annotations

import os
import sys
import tempfile
import time
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

os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="anonymous-client-main-test-")

import crypto  # noqa: E402
import main as client_main  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_client_state():
    """Réinitialise l'état global partagé du module client entre
    chaque test, pour que les tests ne se contaminent pas les uns les
    autres (le module `main` maintient volontairement un état
    process-wide, comme un vrai client interactif)."""

    client_main.messages.clear()
    client_main.reactions_by_target.clear()
    client_main.local_nicknames.clear()
    client_main.typing_users.clear()
    with client_main.state_lock:
        client_main.own_anonymous_number = None
    yield
    client_main.messages.clear()
    client_main.reactions_by_target.clear()
    client_main.local_nicknames.clear()
    client_main.typing_users.clear()


# ============================================================
# SALONS "SIMPLES" (/join) — dérivation déterministe du secret
# ============================================================

def test_room_simple_is_deterministic_across_clients():
    room_a = crypto.Room.simple("general", "hunter2")
    room_b = crypto.Room.simple("general", "hunter2")
    assert room_a.secret == room_b.secret
    assert room_a.room_id == room_b.room_id


def test_room_simple_differs_by_name_and_password():
    base = crypto.Room.simple("general", "hunter2")
    other_password = crypto.Room.simple("general", "different")
    other_name = crypto.Room.simple("random", "hunter2")
    no_password = crypto.Room.simple("general", None)

    secrets_seen = {base.secret, other_password.secret, other_name.secret, no_password.secret}
    assert len(secrets_seen) == 4  # tous distincts


def test_room_simple_encrypts_and_decrypts_normally():
    room = crypto.Room.simple("general", "hunter2")
    keyring_a = crypto.EpochKeyring(room)
    keyring_b = crypto.EpochKeyring(crypto.Room.simple("general", "hunter2"))

    envelope = crypto.encrypt_message(keyring_a, b"salut depuis un salon simple")
    plaintext = crypto.decrypt_message(keyring_b, envelope)
    assert plaintext == b"salut depuis un salon simple"


# ============================================================
# QUITTER LE SALON ACTIF (/room leave) — pas de commande équivalente
# n'existait avant (régression signalée par l'utilisateur)
# ============================================================

def test_leave_current_room_resets_state_and_ws_generation():
    room = crypto.Room.simple("general", None)
    client_main.set_room("general", room)
    client_main.add_local_message({"id": 1, "room_seq": 1, "content": "hello"})
    client_main.reactions_by_target[1] = {"👍": 1}

    with client_main.state_lock:
        generation_before = client_main.ws_generation

    client_main._leave_current_room()

    with client_main.state_lock:
        assert client_main.current_room_name is None
        assert client_main.current_room is None
        assert client_main.keyring is None
        # Doit avoir changé pour invalider le thread WebSocket abonné
        # à l'ancien salon (voir websocket_listener_async).
        assert client_main.ws_generation != generation_before

    assert client_main.messages == []
    assert client_main.reactions_by_target == {}


def test_room_leave_command_with_no_active_room_does_not_crash(monkeypatch):
    messages = []
    monkeypatch.setattr(client_main, "show_system_message", lambda text: messages.append(text))

    with client_main.state_lock:
        client_main.current_room_name = None

    client_main.handle_room(["leave"])
    assert any("Aucun salon actif" in m for m in messages)


# ============================================================
# RÉACTIONS AGRÉGÉES (jamais leur propre ligne de discussion)
# ============================================================

def test_reaction_entries_never_become_chat_lines():
    client_main.add_local_message({
        "id": 42, "content": "hello", "anonymous_number": 111111,
        "display_name": "Anonymous #111111",
    })

    client_main.add_local_message({
        "id": 43, "is_reaction": True, "reaction_target_id": 42,
        "reaction_emoji": "👍", "content": "👍 en réaction à #42",
    })

    assert len(client_main.messages) == 1  # la réaction n'a pas sa propre ligne
    assert client_main.reactions_by_target[42] == {"👍": 1}


def test_multiple_reactions_aggregate_counts():
    for envelope_id, emoji in enumerate([("👍"), ("👍"), ("😂")], start=1):
        client_main.add_local_message({
            "id": 100 + envelope_id, "is_reaction": True, "reaction_target_id": 7,
            "reaction_emoji": emoji, "content": "peu importe",
        })

    assert client_main.reactions_by_target[7] == {"👍": 2, "😂": 1}


def test_duplicate_reaction_envelope_not_double_counted():
    """L'écho local optimiste ET la diffusion WebSocket peuvent toutes
    les deux livrer la MÊME réaction (même id d'enveloppe) : elle ne
    doit être comptée qu'une fois."""

    entry = {
        "id": 999, "is_reaction": True, "reaction_target_id": 7,
        "reaction_emoji": "🔥", "content": "peu importe",
    }
    client_main.add_local_message(dict(entry))
    client_main.add_local_message(dict(entry))  # même id, livré deux fois

    assert client_main.reactions_by_target[7] == {"🔥": 1}


# ============================================================
# VALEURS PAR DÉFAUT : /react ET /reply CIBLENT LE DERNIER MESSAGE
# ============================================================

def test_last_room_seq_ignores_system_lines():
    client_main.add_local_message({"id": None, "room_seq": None, "content": "bienvenue", "system": True})
    client_main.add_local_message({"id": 501, "room_seq": 5, "content": "un vrai message"})
    client_main.add_local_message({"id": None, "room_seq": None, "content": "autre système", "system": True})

    assert client_main._last_room_seq() == 5


def test_last_room_seq_none_when_no_real_message():
    client_main.add_local_message({"id": None, "room_seq": None, "content": "bienvenue", "system": True})
    assert client_main._last_room_seq() is None


def test_last_room_seq_ignores_reactions_and_messages_without_a_number():
    # Un message dont room_seq est None (ex. type inconnu / réaction
    # mal formée tombée ici par erreur) ne doit jamais devenir la
    # cible par défaut d'un /react ou /reply.
    client_main.add_local_message({"id": 10, "room_seq": None, "content": "sans numéro"})
    client_main.add_local_message({"id": 11, "room_seq": 3, "content": "avec numéro"})

    assert client_main._last_room_seq() == 3


# ============================================================
# INDICATEUR DE FRAPPE AGRÉGÉ (façon Discord)
# ============================================================

def test_typing_status_text_empty_when_nobody_typing():
    assert client_main._typing_status_text() == ""


def test_typing_status_text_single_person():
    client_main.typing_users[583921] = time.monotonic()
    text = client_main._typing_status_text()
    assert "583921" in text
    assert "est en train d'écrire" in text


def test_typing_status_text_two_people():
    client_main.typing_users[111111] = time.monotonic()
    client_main.typing_users[222222] = time.monotonic()
    text = client_main._typing_status_text()
    assert "et" in text
    assert "sont en train d'écrire" in text


def test_typing_status_text_more_than_two_collapses():
    client_main.typing_users[111111] = time.monotonic()
    client_main.typing_users[222222] = time.monotonic()
    client_main.typing_users[333333] = time.monotonic()
    assert client_main._typing_status_text() == "Plusieurs personnes sont en train d'écrire..."


def test_typing_status_excludes_own_number():
    with client_main.state_lock:
        client_main.own_anonymous_number = 111111
    client_main.typing_users[111111] = time.monotonic()
    assert client_main._typing_status_text() == ""


def test_typing_status_respects_local_nickname():
    client_main.local_nicknames[583921] = ("Alice", "green")
    client_main.typing_users[583921] = time.monotonic()
    assert client_main._typing_status_text() == "Alice est en train d'écrire..."


def test_stale_typing_entries_are_pruned():
    old_timestamp = time.monotonic() - (client_main.TYPING_EXPIRY_SECONDS + 5)
    client_main.typing_users[583921] = old_timestamp
    removed = client_main._prune_stale_typing()
    assert removed is True
    assert 583921 not in client_main.typing_users


# ============================================================
# SUGGESTIONS DE COMMANDES ET UTILITAIRES D'AFFICHAGE
# ============================================================

def test_matching_commands_filters_by_prefix():
    matches = client_main._matching_commands("/re")
    names = [m[0] for m in matches]
    assert "/reply" in names
    assert "/react" in names
    assert "/room" not in names  # ne commence pas par "/re"


def test_matching_commands_shows_single_reminder_once_args_started():
    matches = client_main._matching_commands("/react 1")
    assert len(matches) == 1
    assert matches[0][0] == "/react"


def test_matching_commands_empty_for_plain_text():
    assert client_main._matching_commands("salut tout le monde") == []


def test_human_size_formatting():
    assert client_main._human_size(500) == "500 o"
    assert client_main._human_size(2048) == "2.0 Ko"
    assert client_main._human_size(5 * 1024 * 1024) == "5.0 Mo"


# ============================================================
# RÉGRESSION : ENTRÉE NE FAISAIT PLUS RIEN (get_wch renvoie parfois
# "\n"/"\r" en chaîne plutôt que curses.KEY_ENTER en entier)
# ============================================================

class _FakeWindow:
    """Simule juste ce qu'input_loop attend de `window`, sans curses
    initialisé (pas de vrai terminal dans les tests)."""

    def __init__(self, keys):
        self.keys = list(keys)

    def keypad(self, value):
        pass

    def nodelay(self, value):
        pass

    def get_wch(self):
        return self.keys.pop(0)


def _run_input_loop_with_keys(monkeypatch, keys):
    import curses as curses_module

    monkeypatch.setattr(client_main, "draw_chat", lambda *a, **k: None)
    sent_messages = []
    handled_commands = []
    monkeypatch.setattr(client_main, "send_text_message", lambda text: sent_messages.append(text))
    monkeypatch.setattr(client_main, "handle_command", lambda text: (handled_commands.append(text), False)[1])

    client_main.running = True
    window = _FakeWindow(keys)

    try:
        client_main.input_loop(window)
    except IndexError:
        pass  # plus de touches simulées à consommer : fin normale du test

    return sent_messages, handled_commands


def test_enter_as_integer_sends_message(monkeypatch):
    import curses

    sent, _ = _run_input_loop_with_keys(monkeypatch, ["s", "a", "l", "u", "t", curses.KEY_ENTER])
    assert sent == ["salut"]


def test_enter_as_newline_string_sends_message(monkeypatch):
    """Régression réelle : `get_wch()` peut livrer Entrée comme la
    CHAÎNE "\\n" plutôt qu'un entier spécial — dans ce cas, Entrée ne
    faisait plus RIEN (ni message, ni commande) car "\\n" tombait dans
    la branche texte et n'est pas imprimable."""

    sent, _ = _run_input_loop_with_keys(monkeypatch, ["c", "v", "\n"])
    assert sent == ["cv"]


def test_enter_as_carriage_return_string_triggers_command(monkeypatch):
    _, handled = _run_input_loop_with_keys(monkeypatch, ["/", "h", "e", "l", "p", "\r"])
    assert handled == ["/help"]


def test_accented_and_emoji_characters_are_typed_correctly(monkeypatch):
    sent, _ = _run_input_loop_with_keys(monkeypatch, ["é", "t", "é", " ", "😀", 13])
    assert sent == ["été 😀"]


def test_backspace_as_string_works():
    import curses as curses_module

    is_backspace = "\x7f" in (curses_module.KEY_BACKSPACE, 127, 8, "\x7f", "\b")
    assert is_backspace


# ============================================================
# COMPLÉTION PAR TABULATION (Tab -> première commande proposée) —
# absente avant (régression signalée par l'utilisateur : Tab ne
# faisait rien)
# ============================================================

def test_tab_completes_to_first_suggested_command(monkeypatch):
    # "/jo" + Tab -> complète en "/join " (seule commande qui matche),
    # puis on tape l'argument et Entrée envoie la commande complète.
    keys = list("/jo") + [9] + list("test") + [13]
    _, handled = _run_input_loop_with_keys(monkeypatch, keys)
    assert handled == ["/join test"]


def test_tab_does_nothing_once_arguments_have_started(monkeypatch):
    # Après un espace, il n'y a plus de nom de commande à compléter :
    # Tab ne doit pas effacer/modifier ce qui a déjà été tapé.
    keys = list("/join general") + [9] + [13]
    _, handled = _run_input_loop_with_keys(monkeypatch, keys)
    assert handled == ["/join general"]


def test_tab_does_nothing_when_no_command_matches(monkeypatch):
    keys = list("/zzz") + [9] + [13]
    sent, handled = _run_input_loop_with_keys(monkeypatch, keys)
    # Rien à compléter : "/zzz" part tel quel (interprété comme
    # commande inconnue par handle_command, mocké ici).
    assert handled == ["/zzz"]


# ============================================================
# RÉGRESSION : LE PROMPT DE CHEMIN (téléchargement, etc.) N'ACCEPTAIT
# PAS ENTRÉE SOUS SA FORME CHAÎNE "\n"/"\r" — même bug de fond que
# celui déjà corrigé dans input_loop, mais jamais appliqué ici :
# taper un chemin de destination personnalisé puis Entrée ne faisait
# RIEN sur un terminal livrant Entrée comme chaîne.
# ============================================================

class _FakePromptScreen:
    def __init__(self, keys):
        self.keys = list(keys)

    def getmaxyx(self):
        return (24, 80)

    def get_wch(self):
        return self.keys.pop(0)

    def refresh(self):
        pass


def _run_prompt_line(monkeypatch, keys, default=""):
    monkeypatch.setattr(client_main, "screen", _FakePromptScreen(keys))
    monkeypatch.setattr(client_main.curses, "curs_set", lambda *a: None)
    monkeypatch.setattr(client_main.curses, "color_pair", lambda *a: 0)
    monkeypatch.setattr(client_main, "safe_addstr", lambda *a, **k: None)
    return client_main._prompt_line("Destination", default)


def test_prompt_line_accepts_enter_as_newline_string(monkeypatch):
    result = _run_prompt_line(monkeypatch, list("/tmp/x.bin") + ["\n"])
    assert result == "/tmp/x.bin"


def test_prompt_line_accepts_enter_as_carriage_return_string(monkeypatch):
    result = _run_prompt_line(monkeypatch, list("/tmp/y.bin") + ["\r"])
    assert result == "/tmp/y.bin"


def test_prompt_line_accepts_enter_as_integer(monkeypatch):
    import curses

    result = _run_prompt_line(monkeypatch, list("/tmp/z.bin") + [curses.KEY_ENTER])
    assert result == "/tmp/z.bin"


def test_prompt_line_escape_cancels_and_keeps_default(monkeypatch):
    result = _run_prompt_line(monkeypatch, list("/tmp/discarded") + [27], default="/tmp/default.bin")
    assert result == "/tmp/default.bin"


def test_prompt_line_backspace_as_string_works(monkeypatch):
    result = _run_prompt_line(monkeypatch, list("/tmp/zz") + ["\x7f", "\x7f"] + list("ab") + ["\n"])
    assert result == "/tmp/ab"


# ============================================================
# DOSSIER DE TÉLÉCHARGEMENT PAR DÉFAUT (~/Downloads, compatible
# Windows et Linux) — pointait auparavant vers un sous-dossier caché
# des données de l'app (XDG data home), jamais ce qu'un utilisateur
# attend comme destination par défaut.
# ============================================================

def test_downloads_dir_points_to_home_downloads(monkeypatch, tmp_path):
    # Pas de `import storage` frais ici : `server/src/storage.py` et
    # `client/src/storage.py` portent le même nom de module, et selon
    # l'ordre de collecte des autres fichiers de test, `sys.modules`
    # peut pointer vers L'UN OU L'AUTRE au moment de l'exécution (voir
    # l'en-tête d'isolation de ce fichier). `client_main.store` est en
    # revanche déjà le bon objet, résolu correctement à la collecte de
    # CE fichier — on réutilise directement sa classe.
    ClientStore = type(client_main.store)
    # `HOME` n'est lu par `Path.home()` que sur Linux/macOS — sur
    # Windows, pathlib utilise `USERPROFILE`/`HOMEDRIVE`+`HOMEPATH` à
    # la place, donc monkeypatcher la variable d'environnement ne
    # fonctionne pas sur les deux plateformes (régression réelle vue
    # en CI Windows : le test touchait le VRAI dossier Downloads de
    # l'utilisateur au lieu du `tmp_path` isolé). On patche directement
    # `Path.home()`, identique quel que soit l'OS.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    store = ClientStore(base_dir=tmp_path / "appdata")
    result = store.downloads_dir
    assert result == tmp_path / "Downloads"
    assert result.is_dir()


# ============================================================
# HISTORIQUE LOCAL DE SAISIE (flèches haut/bas)
# ============================================================

@pytest.fixture(autouse=True)
def _reset_input_history():
    client_main.input_history.clear()
    client_main._history_index = None
    client_main._history_draft = ""
    yield
    client_main.input_history.clear()
    client_main._history_index = None
    client_main._history_draft = ""


def test_up_arrow_recalls_previous_entries(monkeypatch):
    import curses

    keys = list("hello") + [curses.KEY_ENTER]
    keys += list("world") + [curses.KEY_ENTER]
    # Haut, Haut -> remonte de "world" (le plus récent) à "hello".
    keys += [curses.KEY_UP, curses.KEY_UP, curses.KEY_ENTER]

    sent, _ = _run_input_loop_with_keys(monkeypatch, keys)
    assert sent == ["hello", "world", "hello"]


def test_down_arrow_restores_in_progress_draft(monkeypatch):
    import curses

    keys = list("saved") + [curses.KEY_ENTER]
    # Tape un brouillon, remonte dans l'historique (sauvegarde le
    # brouillon), puis redescend : on doit retrouver le brouillon tel
    # quel, pas une entrée de l'historique.
    keys += list("draft")
    keys += [curses.KEY_UP, curses.KEY_DOWN, curses.KEY_ENTER]

    sent, _ = _run_input_loop_with_keys(monkeypatch, keys)
    assert sent == ["saved", "draft"]


def test_consecutive_duplicate_not_recorded_twice():
    client_main._remember_input("ping")
    client_main._remember_input("ping")
    assert client_main.input_history == ["ping"]


def test_fetch_history_clears_stale_reactions_and_aggregates_new_ones(monkeypatch):
    """Régression réelle découverte pendant le scan de bugs : changer
    de salon rechargeait `messages` mais laissait `reactions_by_target`
    intact (fuite d'une réaction d'un salon vers un autre message
    partageant le même room_seq), et l'historique contournait
    `add_local_message` (une réaction de l'historique s'affichait
    comme sa propre ligne de discussion au lieu d'être agrégée)."""

    # État "pollué" par un salon précédent, comme avant un /room use.
    client_main.reactions_by_target[3] = {"👍": 1}
    client_main._seen_reaction_ids.add(999)

    fake_history = [
        {"id": 10, "type": "msg", "room_seq": 1},
        {"id": 11, "type": "reaction", "room_seq": None, "reaction_target_id": 1, "reaction_emoji": "🔥"},
    ]

    def fake_prepare_incoming(raw):
        entry = {"id": raw["id"], "room_seq": raw.get("room_seq"), "content": "x"}
        if raw["type"] == "reaction":
            entry["is_reaction"] = True
            entry["reaction_target_id"] = raw["reaction_target_id"]
            entry["reaction_emoji"] = raw["reaction_emoji"]
        return entry

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"messages": fake_history}

    monkeypatch.setattr(client_main, "prepare_incoming", fake_prepare_incoming)
    monkeypatch.setattr(client_main.requests, "get", lambda *a, **k: _FakeResponse())

    with client_main.state_lock:
        client_main.server_url = "http://example.invalid"
        client_main.current_room_name = "general"

    client_main.fetch_history()

    # La réaction du salon précédent (#3) a disparu...
    assert 3 not in client_main.reactions_by_target
    # ...et la réaction de l'historique du NOUVEAU salon est agrégée
    # sur sa cible (#1), pas affichée comme sa propre ligne.
    assert client_main.reactions_by_target[1] == {"🔥": 1}
    assert len(client_main.messages) == 1
    assert client_main.messages[0]["id"] == 10


def test_history_capped_at_max_size():
    for i in range(client_main.MAX_INPUT_HISTORY + 50):
        client_main._remember_input(f"msg{i}")
    assert len(client_main.input_history) == client_main.MAX_INPUT_HISTORY
    # Les plus anciennes entrées ont été évincées, les plus récentes gardées.
    assert client_main.input_history[-1] == f"msg{client_main.MAX_INPUT_HISTORY + 49}"
