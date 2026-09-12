"""
Boucle périodique légère (asyncio, ~1 fois/minute) qui regroupe tout
ce qui doit se produire régulièrement SANS worker externe (pas de
Celery/Redis) :

- rétention automatique des messages/fichiers (âge, quantité) ;
- nettoyage des sessions éphémères expirées (session.py) ;
- nettoyage des compteurs anti-spam obsolètes (ratelimit.py) ;
- REVÉRIFICATION de `server.toml` : si l'administrateur a modifié le
  fichier pendant que le serveur tourne, les sections rechargeables à
  chaud (voir config.HOT_RELOADABLE_SECTIONS) sont appliquées
  automatiquement, sans attendre un `systemctl reload` explicite ;
- rechargement de la liste de mots bannis si son fichier a changé ;
- extinction + purge d'un serveur temporaire arrivé en fin de vie.

Un message envoyé est immuable : seule cette politique de rétention
(configurée par l'administrateur, jamais par un client) peut supprimer
d'anciens messages.
"""

from __future__ import annotations

import asyncio
import logging
import time

import config as config_module
import database
import moderation
from storage import FileStorage

logger = logging.getLogger("anonymous.retention")


async def run_retention_loop(
    config: dict,
    file_storage: FileStorage,
    session_registry=None,
    interval_seconds: int = 60,
    stop_event: asyncio.Event | None = None,
    progressive_cooldowns: list | None = None,
    on_temporary_expired=None,
    on_config_reloaded=None,
):
    server_start_time = time.monotonic()

    while True:
        # IMPORTANT : on relit `config["retention"]`/`config["messages"]`
        # À CHAQUE itération plutôt qu'une fois avant la boucle, sinon
        # un rechargement à chaud (`reload_hot_fields`, qui remplace
        # ces sous-dictionnaires) ne serait jamais vu ici.
        try:
            run_retention_once(config["retention"], config["messages"], file_storage)
        except Exception:
            logger.exception("échec du passage de rétention")

        if session_registry is not None:
            try:
                session_registry.sweep()
            except Exception:
                logger.exception("échec du nettoyage des sessions expirées")

        for cooldown in progressive_cooldowns or []:
            try:
                cooldown.sweep()
            except Exception:
                logger.exception("échec du nettoyage anti-spam")

        try:
            changed_sections = _check_config_hot_reload()
            if changed_sections and on_config_reloaded is not None:
                on_config_reloaded(changed_sections)
        except Exception:
            logger.exception("échec de la revérification de configuration")

        try:
            _check_banned_words_reload(config)
        except Exception:
            logger.exception("échec du rechargement des mots bannis")

        try:
            await _check_temporary_expiry(config, server_start_time, on_temporary_expired)
        except Exception:
            logger.exception("échec de la vérification du serveur temporaire")

        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                if stop_event.is_set():
                    return
            except asyncio.TimeoutError:
                continue
        else:
            await asyncio.sleep(interval_seconds)


def run_retention_once(retention: dict, messages_config: dict, file_storage: FileStorage) -> None:
    if retention["enabled"] and retention["max_age_seconds"] > 0:
        cutoff = time.time() - retention["max_age_seconds"]
        removed = database.delete_messages_older_than(cutoff)
        if removed:
            logger.info("storage cleanup completed")

        for file_id in database.list_files_older_than(cutoff):
            try:
                file_storage.delete(file_id)
            except (ValueError, OSError):
                pass
            database.delete_file_record(file_id)

    if retention["delete_oldest"]:
        total = database.count_messages()
        max_messages = messages_config["max_messages"]

        if total > max_messages:
            database.delete_oldest_messages(total - max_messages)
            logger.info("storage cleanup completed")


def _check_config_hot_reload() -> list[str]:
    """Revérifie `server.toml` même sans redémarrage ni signal
    explicite. Un fichier devenu invalide entre-temps est IGNORÉ (avec
    un message clair) plutôt que de casser le serveur en cours de
    fonctionnement — voir config.reload_hot_fields. Retourne la liste
    des sections effectivement rechargées (vide si rien n'a changé)."""

    if not config_module.config_file_changed():
        return []

    try:
        changed_sections = config_module.reload_hot_fields()
    except config_module.ConfigError as error:
        logger.error("configuration modifiée mais invalide, ignorée : %s", error)
        return []

    if changed_sections:
        logger.info(
            "configuration rechargée automatiquement (sections : %s)",
            ", ".join(changed_sections),
        )

    return changed_sections


def _check_banned_words_reload(config: dict) -> None:
    moderation_config = config["moderation"]

    if not moderation_config["banned_words_enabled"]:
        return

    path = moderation_config["banned_words_file"]

    if moderation.file_changed(path):
        count = moderation.load_words(path)
        logger.info("liste de mots bannis rechargée (%d entrées)", count)


async def _check_temporary_expiry(config: dict, server_start_time: float, on_expired) -> None:
    temporary = config["temporary"]

    if not temporary["enabled"] or temporary["lifetime_seconds"] <= 0:
        return

    elapsed = time.monotonic() - server_start_time

    if elapsed >= temporary["lifetime_seconds"] and on_expired is not None:
        logger.info("serveur temporaire arrivé en fin de vie — extinction.")
        await on_expired()
