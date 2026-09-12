"""
Sessions éphémères côté serveur.

Une session lie, UNIQUEMENT EN RAM et pour une durée limitée :

    session_id (aléatoire, imprévisible)
        -> clé publique Ed25519 du client pour cette session
        -> numéro pseudonyme "Anonymous #XXXXXX" (aléatoire)
        -> date d'expiration

Rien de tout cela n'est écrit dans SQLite, dans un fichier, ou dans
les logs. Un redémarrage du serveur vide entièrement ce registre :
toutes les sessions précédentes deviennent invalides.

Ce module NE constitue PAS un système de comptes : il n'existe aucune
fonction pour retrouver une session à partir d'un numéro affiché
précédemment, aucune fonction pour lister les sessions par IP, et
aucune persistance. Le seul rôle de ce registre est de permettre au
serveur de vérifier qu'un message signé provient bien de la session
qui a obtenu ce numéro (empêcher l'usurpation), pas de construire un
historique d'identité.
"""

from __future__ import annotations

import dataclasses
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SESSION_ID_BYTES = 32
NUMBER_MIN = 100000
NUMBER_MAX = 999999
_NUMBER_PICK_ATTEMPTS = 50


class InvalidPublicKey(Exception):
    pass


@dataclasses.dataclass
class SessionInfo:
    public_key_bytes: bytes
    anonymous_number: int
    expires_at: float
    is_admin: bool = False


class SessionRegistry:
    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, SessionInfo] = {}
        self._numbers_in_use: set[int] = set()
        self._lock = threading.Lock()
        # Administration éphémère (voir docs/crypto.md "Administration
        # sans identité") : uniquement en RAM, remis à zéro à chaque
        # redémarrage. `_first_claim_used` implémente la règle "premier
        # arrivé, premier servi" quand aucun mot de passe admin n'est
        # configuré — voir `try_claim_admin_first`.
        self._first_claim_used = False

    # -------------------- création --------------------

    def create_session(self, public_key_bytes: bytes) -> tuple[str, int, int]:
        if len(public_key_bytes) != 32:
            raise InvalidPublicKey("une clé publique Ed25519 fait 32 octets.")

        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except Exception as error:
            raise InvalidPublicKey("clé publique Ed25519 invalide.") from error

        session_id = secrets.token_urlsafe(SESSION_ID_BYTES)

        with self._lock:
            self._sweep_locked()
            number = self._pick_number_locked()
            expires_at = time.time() + self.ttl_seconds
            self._sessions[session_id] = SessionInfo(public_key_bytes, number, expires_at)
            self._numbers_in_use.add(number)

        return session_id, number, self.ttl_seconds

    def _pick_number_locked(self) -> int:
        for _ in range(_NUMBER_PICK_ATTEMPTS):
            candidate = NUMBER_MIN + secrets.randbelow(NUMBER_MAX - NUMBER_MIN + 1)
            if candidate not in self._numbers_in_use:
                return candidate

        # Sous très forte charge concurrente seulement : on accepte une
        # collision plutôt que d'échouer la création de session. Une
        # collision n'affaiblit pas la sécurité (chaque session garde
        # sa propre clé publique et sa propre vérification de
        # signature) : elle ne fait que rendre deux affichages visuels
        # identiques par coïncidence.
        return NUMBER_MIN + secrets.randbelow(NUMBER_MAX - NUMBER_MIN + 1)

    # -------------------- vérification --------------------

    def get(self, session_id: str) -> SessionInfo | None:
        if not session_id:
            return None

        with self._lock:
            info = self._sessions.get(session_id)

            if info is None:
                return None

            if info.expires_at < time.time():
                self._forget_locked(session_id)
                return None

            return info

    def verify_signature(self, session_id: str, message: bytes, signature: bytes) -> bool:
        info = self.get(session_id)

        if info is None:
            return False

        try:
            Ed25519PublicKey.from_public_bytes(info.public_key_bytes).verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    # -------------------- nettoyage --------------------

    def _forget_locked(self, session_id: str) -> None:
        info = self._sessions.pop(session_id, None)
        if info is not None:
            self._numbers_in_use.discard(info.anonymous_number)

    def _sweep_locked(self) -> None:
        now = time.time()
        expired = [sid for sid, info in self._sessions.items() if info.expires_at < now]
        for sid in expired:
            self._forget_locked(sid)

    def sweep(self) -> None:
        """Purge périodique des sessions expirées. Appelé par la boucle
        de rétention (retention.py), qui tourne déjà toutes les
        `interval_seconds` — pas besoin d'un worker supplémentaire."""

        with self._lock:
            self._sweep_locked()

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # -------------------- administration éphémère --------------------
    #
    # Voir docs/crypto.md "Administration sans identité". Le statut
    # admin d'une session n'est JAMAIS exposé aux autres clients : ni
    # dans les enveloppes publiques, ni dans /rooms, ni dans /status.
    # Seule la session elle-même (via sa propre requête, prouvée par
    # signature) peut connaître et utiliser son propre statut.

    def mark_admin(self, session_id: str) -> bool:
        with self._lock:
            info = self._sessions.get(session_id)

            if info is None or info.expires_at < time.time():
                return False

            info.is_admin = True
            return True

    def try_claim_admin_first(self, session_id: str) -> bool:
        """Implémente la règle « pas de mot de passe admin configuré =
        la première session qui le demande depuis le démarrage du
        serveur devient admin ». Retourne False si une autre session a
        déjà réclamé ce rôle avant, ou si `session_id` est inconnu."""

        with self._lock:
            info = self._sessions.get(session_id)

            if info is None or info.expires_at < time.time():
                return False

            if self._first_claim_used:
                return False

            info.is_admin = True
            self._first_claim_used = True
            return True

    def is_admin(self, session_id: str) -> bool:
        info = self.get(session_id)
        return bool(info and info.is_admin)
