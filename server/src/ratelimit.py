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
