"""
Rétention automatique des messages et fichiers, selon la configuration
de l'administrateur. Job périodique léger (asyncio, pas de Celery/Redis
nécessaire).

Un message envoyé est immuable : seule cette politique de rétention
(configurée par l'administrateur, jamais par un client) peut supprimer
d'anciens messages.
"""

from __future__ import annotations

import asyncio
import logging
import time

import database
from storage import FileStorage

logger = logging.getLogger("anonymous.retention")


async def run_retention_loop(
    config: dict,
    file_storage: FileStorage,
    session_registry=None,
    interval_seconds: int = 60,
    stop_event: asyncio.Event | None = None,
):
    retention = config["retention"]
    messages_config = config["messages"]

    while True:
        try:
            run_retention_once(retention, messages_config, file_storage)
        except Exception:
            logger.exception("échec du passage de rétention")

        if session_registry is not None:
            try:
                session_registry.sweep()
            except Exception:
                logger.exception("échec du nettoyage des sessions expirées")

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
