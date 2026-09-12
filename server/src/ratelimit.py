"""
Limitation de débit purement en mémoire (RAM), jamais persistée,
jamais journalisée.

Principe important (voir docs/privacy.md) : pour limiter les abus
sans créer de compte utilisateur permanent, on utilise l'adresse IP
de la connexion réseau comme clé *transitoire* d'un compteur en
mémoire. Cette IP :

- n'est JAMAIS écrite sur disque ;
- n'est JAMAIS journalisée ;
- n'est JAMAIS associée à un message stocké ou à son contenu ;
- est oubliée dès l'expiration de sa fenêtre glissante ou au
  redémarrage du serveur.

Ce n'est pas une identité applicative : deux connexions du même
réseau partagent le même compteur, et rien ne permet de relier un
message stocké à cette IP après coup.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()

        with self._lock:
            bucket = self._events.setdefault(key, deque())

            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()

            if len(bucket) >= self.max_events:
                return False

            bucket.append(now)
            return True

    def sweep(self) -> None:
        """Purge périodique des clés inactives pour éviter une
        croissance mémoire non bornée sur un serveur longtemps
        allumé avec beaucoup d'IP différentes."""

        now = time.monotonic()

        with self._lock:
            stale = [
                key
                for key, bucket in self._events.items()
                if not bucket or now - bucket[-1] > self.window_seconds * 4
            ]
            for key in stale:
                del self._events[key]


class ConnectionCounter:
    """Limite le nombre de connexions WebSocket simultanées par IP,
    entièrement en mémoire."""

    def __init__(self, max_per_ip: int):
        self.max_per_ip = max_per_ip
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def try_acquire(self, key: str) -> bool:
        with self._lock:
            current = self._counts.get(key, 0)
            if current >= self.max_per_ip:
                return False
            self._counts[key] = current + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            if key in self._counts:
                self._counts[key] -= 1
                if self._counts[key] <= 0:
                    del self._counts[key]


class ProgressiveCooldown:
    """Cooldown exponentiel par clé (IP) après un dépassement de
    limite : 1s, 2s, 4s, 8s... jusqu'à `max_seconds`, au lieu d'un
    simple rejet fixe (voir docs/server.md "Anti-spam").

    Purement en mémoire (RAM), jamais persisté, jamais journalisé avec
    la clé en clair — voir docs/privacy.md pour le même principe déjà
    appliqué aux compteurs de `SlidingWindowLimiter`."""

    def __init__(self, max_seconds: float):
        self.max_seconds = max_seconds
        self._blocked_until: dict[str, float] = {}
        self._next_penalty: dict[str, float] = {}
        self._lock = threading.Lock()

    def remaining_seconds(self, key: str) -> float:
        with self._lock:
            until = self._blocked_until.get(key)
            if until is None:
                return 0.0
            remaining = until - time.monotonic()
            return remaining if remaining > 0 else 0.0

    def register_violation(self, key: str) -> float:
        """Enregistre un dépassement de limite pour `key` et retourne
        la durée (secondes) du cooldown appliqué."""

        with self._lock:
            penalty = self._next_penalty.get(key, 1.0)
            self._blocked_until[key] = time.monotonic() + penalty
            self._next_penalty[key] = min(penalty * 2, self.max_seconds)
            return penalty

    def register_success(self, key: str) -> None:
        """Une requête normale réduit progressivement la pénalité
        mémorisée, pour qu'une IP redevenue calme ne reste pas punie
        indéfiniment à cause d'un pic ponctuel ancien."""

        with self._lock:
            if key in self._next_penalty:
                self._next_penalty[key] = max(1.0, self._next_penalty[key] / 2)

    def sweep(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [
                key
                for key, until in self._blocked_until.items()
                if until < now - self.max_seconds
            ]
            for key in stale:
                self._blocked_until.pop(key, None)
                self._next_penalty.pop(key, None)
