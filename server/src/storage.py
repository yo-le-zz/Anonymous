"""
Stockage des fichiers chiffrés (blobs opaques) côté serveur.

Le serveur ne connaît ni le nom, ni le type, ni le contenu réel d'un
fichier : ceux-ci sont chiffrés côté client (voir client/src/media.py)
et le serveur ne stocke que des octets sans signification pour lui,
sous un nom de fichier généré aléatoirement.

Protections appliquées :
- noms de fichiers générés côté serveur (jamais fournis par le client) ;
- aucune écriture en dehors du dossier de stockage configuré ;
- vérification de la taille en cours d'écriture (arrêt dès dépassement,
  sans avoir à charger le fichier entier en mémoire) ;
- vérification du quota global de stockage avant et pendant l'écriture ;
- suppression du fichier partiel en cas d'échec/abus.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import AsyncIterator


class StorageQuotaExceeded(Exception):
    pass


class FileTooLarge(Exception):
    pass


class FileStorage:
    def __init__(self, root: str, max_file_size: int, max_storage_bytes: int):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.max_file_size = max_file_size
        self.max_storage_bytes = max_storage_bytes

    def _new_file_id(self) -> str:
        # 24 octets aléatoires -> 32 caractères base64 url-safe environ.
        # Pas d'extension, pas de nom d'origine : rien qui ne fuite le
        # contenu ou ne serve d'identifiant stable côté client.
        return secrets.token_urlsafe(24)

    def _path_for(self, file_id: str) -> Path:
        # `file_id` est toujours généré par ce module (jamais fourni tel
        # quel par un client pour un chemin d'écriture), mais on
        # applique quand même une défense en profondeur contre le path
        # traversal et les caractères de séparation de chemin.
        if "/" in file_id or "\\" in file_id or ".." in file_id:
            raise ValueError("identifiant de fichier invalide.")

        candidate = (self.root / file_id).resolve()

        if self.root.resolve() not in candidate.parents and candidate != self.root.resolve():
            raise ValueError("chemin de fichier hors du dossier de stockage.")

        return candidate

    async def save_stream(
        self,
        chunks: AsyncIterator[bytes],
        current_total_usage: int,
    ) -> tuple[str, int]:
        file_id = self._new_file_id()
        path = self._path_for(file_id)

        written = 0

        try:
            with open(path, "wb") as handle:
                async for chunk in chunks:
                    written += len(chunk)

                    if written > self.max_file_size:
                        raise FileTooLarge(
                            f"fichier trop volumineux (> {self.max_file_size} octets)."
                        )

                    if current_total_usage + written > self.max_storage_bytes:
                        raise StorageQuotaExceeded("quota de stockage du serveur atteint.")

                    handle.write(chunk)

            os.chmod(path, 0o600)

        except Exception:
            if path.exists():
                path.unlink(missing_ok=True)
            raise

        return file_id, written

    def open_for_read(self, file_id: str):
        path = self._path_for(file_id)

        if not path.is_file():
            raise FileNotFoundError(file_id)

        return open(path, "rb")

    def delete(self, file_id: str) -> None:
        path = self._path_for(file_id)
        path.unlink(missing_ok=True)
