"""
Authentification serveur.

Le mot de passe protège l'ACCÈS au serveur, pas l'identité d'un
utilisateur. En conséquence :

- le mot de passe en clair n'est jamais stocké (Argon2id) ;
- une connexion authentifiée reçoit un jeton temporaire, opaque,
  sans lien avec un compte, un profil ou un historique ;
- le jeton n'est jamais persisté côté serveur (gardé en mémoire,
  perdu au redémarrage) ni journalisé ;
- le jeton n'est jamais utilisé comme clé de chiffrement des messages
  et n'est jamais associé à un message dans la base.
"""

from __future__ import annotations

import secrets
import threading
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()

TOKEN_TTL_SECONDS = 6 * 3600
TOKEN_SIZE = 32

_tokens_lock = threading.Lock()
_active_tokens: dict[str, float] = {}  # token -> expiry (aucune donnée liée)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def issue_token() -> str:
    token = secrets.token_urlsafe(TOKEN_SIZE)
    expiry = time.time() + TOKEN_TTL_SECONDS

    with _tokens_lock:
        _active_tokens[token] = expiry
        _prune_locked()

    return token


def verify_token(token: str | None) -> bool:
    if not token:
        return False

    with _tokens_lock:
        expiry = _active_tokens.get(token)

        if expiry is None:
            return False

        if expiry < time.time():
            del _active_tokens[token]
            return False

        return True


def _prune_locked() -> None:
    now = time.time()
    expired = [token for token, expiry in _active_tokens.items() if expiry < now]
    for token in expired:
        del _active_tokens[token]


def extract_bearer_token(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None

    prefix = "Bearer "
    if not authorization_header.startswith(prefix):
        return None

    return authorization_header[len(prefix) :]
