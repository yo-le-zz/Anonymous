# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [1.0.7] — 2026-10-09

### Ajouté (suite — retours d'usage réel sur 1.0.7)
- **`/room leave`** : jusqu'ici, rien ne permettait de quitter le
  salon actif sans se déconnecter entièrement du serveur. Réinitialise
  l'état de salon (clé de chiffrement, abonnement WebSocket) sans
  toucher à la session serveur.
- **`/room new` et `/room join` simplifiés** : ils sont désormais de
  simples alias de `/join` (dérivation déterministe par nom + mot de
  passe optionnel, voir `crypto.Room.simple()`) au lieu de générer/
  exiger une invitation à partager hors bande. `/room new <nom>` crée
  un salon public, `/room new <nom> <mot_de_passe>` un salon protégé,
  et `/room join <nom> [mot_de_passe]` rejoint directement — plus
  d'étape d'invitation intermédiaire. Le compromis de confidentialité
  que cela implique (le serveur connaît nom + mot de passe, voir
  docs/crypto.md §13) est rappelé à l'utilisateur au moment de
  rejoindre.
- **Tab complète la première commande proposée** : les suggestions
  au-dessus de la ligne de saisie n'étaient qu'un affichage passif.
  Tab insère désormais directement la première commande suggérée
  (tant que le nom de la commande est encore en cours de frappe).

### Corrigé (suite)
- **Suite CI Windows en échec** (`test_downloads_dir_points_to_home_downloads`) :
  le test simulait un dossier personnel isolé via la variable
  d'environnement `HOME`, qui n'est lue par `Path.home()` que sur
  Linux/macOS — sur Windows, pathlib utilise `USERPROFILE` à la place.
  Le test touchait donc le VRAI dossier Downloads de la machine CI au
  lieu du dossier temporaire isolé. Corrigé en patchant directement
  `Path.home()`, identique quel que soit l'OS. (`downloads_dir`
  lui-même était déjà correct — seul le test ne portait pas.)
- **Impossible de valider un chemin de destination personnalisé au
  téléchargement d'un fichier** : même bug qu'Entrée dans la boucle de
  saisie principale (corrigé en 1.0.6), mais dans le prompt de
  destination (`_prompt_line`) qui ne l'avait pas reçu — Entrée n'y
  était testée que sous sa forme entière, pas sous la forme chaîne
  ("\n"/"\r") que `get_wch()` peut aussi renvoyer selon le terminal.
  Taper son propre chemin et appuyer sur Entrée ne faisait donc rien.
- **Dossier de destination par défaut** pour les téléchargements :
  utilise désormais le vrai dossier `~/Downloads` de l'utilisateur
  (identique sous Windows et Linux/macOS) au lieu d'un sous-dossier
  caché des données de l'application, qui n'est jamais ce à quoi on
  s'attend et rendait les fichiers téléchargés difficiles à retrouver.
- **Permissions du fichier de configuration serveur à l'installation**
  (`server/debian/postinst`) : le paquet livre `server.toml` en 0644,
  et le `chown`/`chmod` censé le resserrer à l'installation avalait
  silencieusement toute erreur (`|| true`) — un échec (droits
  insuffisants, SELinux...) laissait le fichier root:root 0644, lisible
  par n'importe quel utilisateur du système, alors qu'il peut contenir
  un hash de mot de passe. Les commandes sont désormais bloquantes :
  un échec fait échouer l'installation plutôt que de se terminer avec
  des permissions fausses sans le signaler.

### Ajouté
- **Numérotation des messages propre à chaque salon** (`room_seq`) :
  le `#N` affiché devant chaque message repart de 1 dans chaque salon
  au lieu d'utiliser l'id global en base. Les réactions (et les
  échanges de clé) ne consomment JAMAIS ce numéro — seuls `msg` et
  `file` en consomment un, exactement comme avant pour l'agrégation
  des réactions, mais désormais sans collision entre salons distincts
  partageant le même numéro. Migration automatique (`ALTER TABLE` +
  rétro-remplissage `ROW_NUMBER() OVER (PARTITION BY room ...)`) pour
  les bases déjà en production.
- **`/download <N>`** accepte désormais le numéro affiché devant un
  message-fichier (le même `#N` que `/react`/`/reply`) en plus du
  file_id brut (gardé pour compatibilité ascendante) : plus besoin de
  recopier un UUID illisible à la main. Le message ne l'affiche plus
  dans son contenu — `/download` tout court suffit pour le dernier
  fichier reçu.
- **Historique local de saisie** (flèches haut/bas, comme un shell) :
  rappelle les commandes et messages déjà tapés pendant la connexion
  en cours (jamais envoyé au serveur ni persisté entre sessions),
  avec préservation du brouillon en cours si on redescend au-delà du
  message le plus récent.

### Corrigé
- **Une réaction pouvait s'afficher sur le mauvais message après un
  changement de salon.** Changer de salon (`/room use`, `/join`, une
  reconnexion) vidait `messages` mais pas l'agrégat des réactions : une
  réaction du salon précédent pouvait rester accrochée à un message du
  nouveau salon partageant le même numéro `#N` (la numérotation repart
  de 1 dans chaque salon — voir ci-dessus). Les deux sont désormais
  réinitialisés ensemble à chaque changement de salon.
- **Une réaction de l'historique s'affichait comme sa propre ligne de
  discussion** au lieu d'être agrégée à côté du message qu'elle cible :
  l'historique rechargé au changement de salon contournait
  `add_local_message` (qui fait l'agrégation) en ajoutant les messages
  directement à la liste affichée. Il repasse désormais par le même
  chemin que les messages reçus en direct.
- **Workflow de release Docker en échec** (`repository name must be
  lowercase`) : `ghcr.io/<repo>/...` utilisait `github.repository` tel
  quel, qui garde la casse réelle du dépôt GitHub (ex. un `A`
  majuscule) alors que Docker exige un nom entièrement en minuscules.
  Le nom d'image est désormais calculé en minuscules une fois, puis
  réutilisé pour les deux tags.
- **Build Windows bloqué en CI** sur l'invite interactive de Nuitka
  ("Proceed and download? [Yes]/No", pour Dependency Walker) :
  non-interactif, le run restait bloqué jusqu'au timeout. Ajout de
  `--assume-yes-for-downloads` aux deux compilations Nuitka
  (client et serveur) sur le runner Windows, et par cohérence/défense
  à `build.sh` (Linux) et `build-windows-cross.sh` (Wine).
- **`build-windows-cross.sh` échouait à l'installation de Nuitka**
  (`Cannot import 'setuptools.build_meta'`) : le Python "embeddable"
  Windows n'a pas de backend de build disponible pour construire les
  paquets qui n'ont pas de roue précompilée pour cette configuration
  (le cas de `nuitka`, installé depuis son sdist). Ajout d'une mise à
  jour explicite de `pip`/`setuptools`/`wheel` avant les autres
  installations.

## [1.0.6] — 2026-09-14

### Corrigé
- **Régression critique : Entrée n'envoyait plus rien** (ni message,
  ni commande), introduite par le passage à `get_wch()` en v1.0.5 pour
  corriger la saisie Unicode. Selon le terminal, `get_wch()` livre la
  touche Entrée soit comme l'entier `curses.KEY_ENTER`, soit comme la
  CHAÎNE `"\n"`/`"\r"` — le code ne testait Entrée que dans le cas
  entier, donc la chaîne tombait dans la branche "texte", n'était pas
  imprimable, et disparaissait silencieusement. Entrée (et Backspace,
  vulnérable au même problème) sont désormais détectés indépendamment
  du type retourné. Testé avec les deux formes, plus une
  non-régression sur la saisie accentuée/emoji corrigée en 1.0.5.

## [1.0.5] — 2026-09-13

### Corrigé
- **Impossible de taper des accents ou des emoji** (ex. chemins comme
  `/home/ilan/Téléchargements`, réactions emoji) : le client
  n'appelait jamais `locale.setlocale(locale.LC_ALL, "")` et utilisait
  `getch()` (ASCII strict, 0-255) au lieu de `get_wch()` (Unicode).
  Toute touche accentuée ou emoji était silencieusement perdue.
  Corrigé — testé avec des accents et des emoji réels dans un message.
- **Couleur des pseudos locaux (`/nick`) jamais appliquée** (seul le
  nom l'était) : `draw_chat` ne consultait pas la couleur enregistrée.
  Corrigé.
- **Le même message d'indisponibilité s'affichait en rafale** :
  ce n'était pas un doublon de code mais l'absence de regroupement —
  chaque message non déchiffrable de l'historique (ex. reçu avant
  d'avoir choisi un salon) produisait sa propre ligne identique. Les
  lignes consécutives identiques sont désormais regroupées
  (`"... (×N)"`).

### Ajouté
- **Salons "simples"** (`/join <salon> [mot_de_passe]`) : rejoint ou
  crée un salon public/protégé par mot de passe SANS partage
  d'invitation hors bande. Le secret de chiffrement est dérivé du nom
  (+ mot de passe), avec un avertissement clair et honnête affiché à
  l'utilisation : ce mode protège contre un observateur réseau passif,
  **pas** contre le serveur lui-même (qui voit nécessairement le nom
  et le mot de passe). `/room new` + invitation hors bande reste
  disponible pour une confidentialité garantie même contre le serveur
  — voir docs/crypto.md §13.
- **Réactions et réponses sans avoir à compter les id** : `/react` et
  `/reply` ciblent le DERNIER message par défaut ; `/react` seul
  affiche un menu de 8 emoji prédéfinis numérotés. Les réactions
  s'affichent désormais agrégées à côté du message ciblé
  (`👍×2 😂×1`) au lieu de créer une ligne de discussion séparée par
  réaction.
- **Indicateur de frappe dynamique façon Discord** : ligne persistante
  juste au-dessus de la zone de saisie (pas une suite de messages
  système), qui agrège les noms ("X et Y sont en train d'écrire"),
  bascule sur "Plusieurs personnes sont en train d'écrire..." au-delà
  de deux, disparaît quand la personne arrête d'écrire ou tape une
  commande, et s'auto-purge après quelques secondes d'inactivité si le
  signal d'arrêt a été perdu (déconnexion brutale).
- **Suggestions de commandes** : dès que la saisie commence par `/`,
  jusqu'à 5 commandes correspondantes s'affichent au-dessus de la zone
  de texte avec leur gabarit d'arguments, pour réduire le
  copier-coller depuis `/help`.
- **Téléchargement de fichier amélioré** (`/download [id]`) : id
  optionnel (dernier fichier reçu par défaut), aperçu (nom, taille,
  type) avant de télécharger, et invite interactive pour choisir/
  confirmer le chemin de destination (avec confirmation avant d'écraser
  un fichier existant).
- **Numéro de message affiché** en petit devant chaque ligne de
  discussion, pour cibler manuellement un message plus ancien avec
  `/reply <id> ...` ou `/react ... <id>` quand la valeur par défaut
  (dernier message) ne convient pas.
- **`build-windows-cross.sh`** (expérimental) : tentative de
  cross-compilation Windows depuis Linux via Wine, pour un test rapide
  en local. Documenté honnêtement comme non fiable — Nuitka ne
  supporte pas la compilation croisée au sens strict, et certaines
  dépendances (code C compilé) peuvent échouer sous Wine. La voie
  officielle pour les releases reste la compilation native sur un
  runner Windows (`.github/workflows/release.yml`), déjà en place.

## [1.0.4] — 2026-09-11

### Ajouté
- **Réactions** (`/react <id> <emoji>`) et **réponses** (`/reply <id> <texte>`),
  chiffrées de bout en bout comme n'importe quel message. Les
  réactions sont réellement activables/désactivables côté serveur
  (`[features] reactions_enabled`, le type d'enveloppe étant visible
  sans déchiffrement) ; les réponses sont indicatives (le contenu
  chiffré n'est jamais inspectable par le serveur).
- **Pseudos et couleurs locaux** (`/nick <numéro> <nom> [couleur]`) :
  jamais envoyés au serveur, jamais persistés d'une session à l'autre
  (le numéro change à chaque connexion — les persister tromperait sur
  l'identité réelle derrière un numéro futur).
- **Administration éphémère sans identité** (`[admin]`, voir
  docs/crypto.md) : la première session qui le demande devient admin
  si aucun mot de passe admin n'est configuré, sinon quiconque connaît
  ce mot de passe le devient. Le statut n'est **jamais** exposé aux
  autres clients. Commandes client `/admin claim|reload|room-password`,
  endpoints serveur `/admin/claim`, `/admin/reload`,
  `/admin/rooms/password` (rotation de mot de passe de salon sans
  perte d'historique), tous protégés par signature Ed25519.
- **Anti-spam progressif** (`[ratelimit] progressive_cooldown_enabled`) :
  cooldown qui double à chaque récidive (1s, 2s, 4s...) au lieu d'un
  rejet fixe, avec en-tête `Retry-After`. Toujours annoncé via
  `/server-info`.
- **Mode `[privacy] e2ee = false`** explicite (désactivé par défaut) :
  seul mode où une modération par mots bannis (`[moderation]`) est
  réellement appliquée côté serveur. En E2EE (mode par défaut), la
  même liste n'est publiée que via `GET /policy`, à titre indicatif
  pour un filtrage côté client — jamais une garantie.
- **Page web publique** (`/`), `/status`, `/api/stats`, `/policy` —
  zéro ressource externe, zéro tracking, agrégats uniquement.
- **Indicateurs de frappe** en direct (WebSocket), jamais stockés.
- **Rechargement à chaud réel** : `server.toml` est revérifié
  automatiquement toutes les ~60 secondes (et via `SIGHUP` /
  `systemctl reload` / `anonymous-server reload` / `/admin/reload`) ;
  les sections sûres (limites, fonctionnalités, modération, salons,
  page web, rétention) sont appliquées sans redémarrage. Un fichier
  devenu invalide entre-temps est ignoré (l'ancienne configuration
  valide continue de tourner) plutôt que de casser le serveur.
- **CLI classique** : `anonymous-server --version`, `--help`,
  `--config PATH`, et sous-commandes `hash-password`,
  `generate-admin-password-hash`, `check-config`, `stats`, `cleanup`,
  `reload`, `config` (assistant interactif).
- **Assistant de configuration visuel** (`anonymous-server config`) :
  navigation au clavier, explication de chaque option et de sa valeur
  actuelle, retour arrière libre, écriture du `server.toml` résultant.
- **Mode serveur temporaire** (`[temporary]`) : purge totale des
  messages/fichiers puis extinction automatique après une durée fixée.
- **Docker** : `server/Dockerfile` + `docker-compose.yml`, image
  publiée sur `ghcr.io` à chaque tag de version.
- **Build multiplateforme** : le workflow de release construit et
  teste désormais aussi sur déclenchement manuel
  (`workflow_dispatch`), sans publier de Release GitHub hors tag.

### Corrigé
- **`config.py` ne doit plus jamais crasher à l'import** sur un
  fichier invalide : `anonymous-server --version`/`check-config`
  fonctionnent maintenant même avec une configuration cassée (avant,
  ils plantaient avec une trace Python brute).
- **`add_signal_handler(SIGHUP)` faisait planter le serveur** quand la
  boucle asyncio ne tournait pas dans le thread principal (observé en
  testant — `RuntimeError: set_wakeup_fd only works in main thread`).
  Le rechargement par signal se dégrade proprement dans ce cas (reste
  disponible via `/admin/reload` et la revérification périodique).
- **Rechargement à chaud sans effet réel sur les limites de débit** :
  les objets de limitation de débit étaient construits une fois au
  démarrage et ne relisaient jamais `Config` — `[ratelimit]` modifié à
  chaud n'avait donc aucun effet avant redémarrage. Corrigé
  (`_apply_ratelimit_config`, appelée après chaque rechargement).

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
