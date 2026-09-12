"""
Modération basée sur une liste de mots bannis.

IMPORTANT — voir docs/privacy.md et docs/crypto.md : quand
`[privacy] e2ee = true` (valeur par défaut), le serveur NE PEUT PAS
STRUCTURELLEMENT appliquer ce filtre sur le contenu des messages,
puisqu'il ne reçoit jamais leur texte en clair. Dans ce mode, la seule
utilisation légitime de cette liste est de la publier via `GET
/policy` pour que les CLIENTS l'appliquent eux-mêmes avant
chiffrement — une politique indicative, jamais une garantie : un
client modifié peut toujours l'ignorer. Ne prétendez jamais le
contraire à vos utilisateurs.

Le filtrage n'est réellement exécuté côté serveur QUE si
`[privacy] e2ee = false` est explicitement configuré (voir main.py),
auquel cas les messages arrivent en clair (algorithm="none") et
peuvent être inspectés avant stockage.
"""

from __future__ import annotations

import threading
from pathlib import Path

_lock = threading.Lock()
_words: set[str] = set()
_loaded_path: str | None = None
_loaded_mtime: float | None = None


def load_words(path: str) -> int:
    """(Re)charge la liste depuis le disque. Retourne le nombre de mots
    chargés. Un fichier absent ou vide réinitialise la liste plutôt que
    de lever une exception : un problème de modération ne doit jamais
    faire planter le serveur."""

    global _words, _loaded_path, _loaded_mtime

    words: set[str] = set()
    file_path = Path(path) if path else None
    mtime = None

    if file_path and file_path.exists():
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                word = line.strip().lower()
                if word and not word.startswith("#"):
                    words.add(word)
            mtime = file_path.stat().st_mtime
        except OSError:
            words = set()
            mtime = None

    with _lock:
        _words = words
        _loaded_path = path
        _loaded_mtime = mtime

    return len(words)


def file_changed(path: str) -> bool:
    """Utilisé pour la revérification périodique (voir retention.py) :
    évite de relire le fichier à chaque message, seulement quand son
    contenu a effectivement changé sur disque."""

    if not path:
        return False

    file_path = Path(path)
    if not file_path.exists():
        return False

    try:
        current_mtime = file_path.stat().st_mtime
    except OSError:
        return False

    with _lock:
        return _loaded_path != path or _loaded_mtime != current_mtime


def word_count() -> int:
    with _lock:
        return len(_words)


def current_words() -> list[str]:
    with _lock:
        return sorted(_words)


def contains_banned_word(text: str) -> str | None:
    """Retourne le premier mot banni trouvé (insensible à la casse,
    correspondance de sous-chaîne simple) ou None. Volontairement
    basique — voir la limite documentée en tête de ce module : ce
    n'est PAS un filtre infaillible, et il n'est de toute façon appelé
    que lorsque `privacy.e2ee = false` (voir main.py)."""

    lowered = text.lower()

    with _lock:
        words = list(_words)

    for word in words:
        if word in lowered:
            return word

    return None
