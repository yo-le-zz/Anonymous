# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.0.3] — 2026-09-08

### Corrigé
- **Client compilé (Nuitka) incapable de se connecter en temps réel** :
  `⚠ Flux temps réel indisponible (No module named 'websockets.asyncio')`.
  La bibliothèque `websockets` (>= 13) utilise un mécanisme d'imports
  paresseux (`__getattr__` au niveau module, PEP 562) pour charger
  `websockets.asyncio.client` seulement au moment où
  `websockets.connect` est réellement utilisé. Ce genre d'import
  dynamique est invisible à l'analyse statique de Nuitka
  (`--follow-imports` ne le détecte pas), donc le sous-module n'était
  jamais embarqué dans le binaire compilé — le programme fonctionnait
  normalement en source (`python main.py`) mais échouait une fois
  packagé. `build.sh` et `.github/workflows/release.yml` demandent
  désormais explicitement `--include-module=websockets.asyncio.client`
  à Nuitka. Reproduit et vérifié avec un binaire réellement compilé
  avant/après correctif (l'erreur exacte de l'utilisateur a été
  reproduite à l'identique sans le flag, puis résolue avec).
- Ajout de `--include-package=cryptography`/`requests` (client) et
  `--include-package=uvicorn`/`starlette`/`fastapi`/`pydantic`/
  `websockets`/`argon2`/`cryptography` (serveur) par précaution
  défensive : ces bibliothèques ont des historiques connus d'imports
  conditionnels ou différés selon la plateforme, susceptibles de
  passer inaperçus à l'analyse statique dans d'autres configurations.

## [1.0.2] — 2026-09-08

### Corrigé
- **Bug critique de démarrage sur mise à jour** : sur une base SQLite
  déjà existante (créée par une version antérieure du serveur),
  `CREATE TABLE IF NOT EXISTS` ne modifie jamais une table déjà
  présente. Une base créée avant l'introduction de la colonne `room`
  (v1.0.1) — ou même avant `anonymous_number` (v1.0.0) — faisait donc
  planter le serveur au démarrage avec
  `sqlite3.OperationalError: no such column: room`, en boucle de
  redémarrage systemd infinie. `database.init_database()` applique
  désormais de vraies migrations incrémentales (`ALTER TABLE ... ADD
  COLUMN`) pour chaque colonne manquante détectée, avec des valeurs
  par défaut neutres pour les lignes déjà existantes (`room='general'`,
  `anonymous_number=0` — cette dernière valeur n'est jamais attribuée
  à une vraie session, dont les numéros vont de 100000 à 999999).
  Testé explicitement pour une remise à niveau depuis n'importe quelle
  version antérieure (voir
  `test_migration_adds_missing_columns_to_preexisting_database`).

## [1.0.1] — 2026-09-07

### Corrigé
- **Envoi de message silencieusement bloqué après un changement de
  salon** : le WebSocket restait abonné à l'ancien salon indéfiniment
  (`recv()` sans timeout ne revérifiait jamais son état). Changer de
  salon force désormais une reconnexion WebSocket sur le nouveau
  salon, et la boucle de réception revérifie son état toutes les 5
  secondes au lieu de bloquer indéfiniment.
- **Message envoyé non affiché immédiatement** : le client attendait
  la diffusion WebSocket pour afficher son propre message envoyé. Un
  écho local optimiste est désormais affiché dès la confirmation du
  `POST /messages`, la diffusion WebSocket restant le mécanisme normal
  pour les autres participants (déduplication par id).
- **Silence total en cas de panne WebSocket** : après plusieurs
  échecs de connexion consécutifs, un message système visible
  informe désormais l'utilisateur plutôt que de ne rien afficher.
- **Historique non protégé par le mot de passe serveur** :
  `GET /messages` et `GET /messages/{id}` ne vérifiaient pas
  l'authentification même quand `auth.enabled = true`, ce qui rendait
  la protection par mot de passe inutile pour la lecture. Corrigé.
- **Robustesse face aux versions de `websockets`** : le paramètre du
  client a été renommé `extra_headers` → `additional_headers` entre
  les versions 12 et 13 de la bibliothèque ; le client s'adapte
  désormais automatiquement, et la dépendance minimale est relevée à
  `websockets>=13.0`.
- **`uvicorn.run("main:app", ...)` remplacé par `uvicorn.run(app, ...)`**
  : la référence par chaîne de caractères au module ne fonctionne pas
  de façon fiable une fois le serveur compilé en exécutable autonome
  (Nuitka) ; passer directement l'objet `app` est portable dans tous
  les contextes de déploiement (source, `.deb`, binaire Windows).

### Ajouté
- **Salons (rooms) côté serveur** : un message appartient désormais à
  un salon (canal de nommage, PAS une identité utilisateur). Un salon
  peut être public (création libre selon la politique du serveur) ou
  protégé par un mot de passe (Argon2id, jamais stocké en clair,
  jamais journalisé). Nouveaux endpoints `GET/POST /rooms`. La
  diffusion WebSocket et l'historique sont désormais isolés par
  salon.
- Commandes client `/room list` (salons locaux + salons du serveur
  connecté), `/room new <nom> [mot_de_passe]`, et
  `/room password <nom> [mot_de_passe]`.
- Configuration serveur `[rooms]` : `enabled`, `allow_public_rooms`,
  `max_rooms`, `max_room_name_length`, `default_room`.
- Packaging Linux sans dépendance à un outil tiers : `build.sh`
  compile avec Nuitka (`--onefile`) puis assemble les `.deb`
  directement avec `dpkg-deb`.
- Workflows GitHub Actions :
  - `ci.yml` — suite de tests sur Linux et Windows à chaque push/PR,
    plus une vérification indépendante du schéma SQLite réel.
  - `release.yml` — sur chaque tag `vX.Y.Z`, build automatique des
    binaires et paquets Linux (`.deb`, `.tar.gz`) et Windows (`.zip`),
    publiés sur la GitHub Release correspondante.
- Dépendance conditionnelle `windows-curses` (uniquement sur
  `sys_platform == 'win32'`), nécessaire pour compiler le client sous
  Windows où le module `curses` n'existe pas nativement.

### Retiré
- Dépendance à l'outil tiers `meb` pour le packaging `.deb`
  (`meb.toml`, `meb-server.toml` supprimés).

## [1.0.0] — Version initiale (V2)

Réécriture complète du projet Anonymous : chiffrement de bout en bout
(X25519 + HKDF-SHA256 + AES-256-GCM/ChaCha20-Poly1305), sessions
éphémères signées (Ed25519, numéro pseudonyme "Anonymous #XXXXXX"),
suppression de toute identité persistante (`client_token`,
`owner_token_hash`, édition/suppression de message), fichiers chiffrés
côté client, rétention automatique, mot de passe serveur (Argon2id),
service systemd durci, documentation complète (`docs/crypto.md`,
`docs/privacy.md`, `docs/architecture.md`, `docs/server.md`,
`docs/https.md`).
