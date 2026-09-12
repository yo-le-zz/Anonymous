# Modèle de menace et confidentialité — docs/privacy.md

Ce document explique, ligne par ligne, ce que le serveur Anonymous
connaît, ce qu'il ne connaît jamais, et pourquoi. Il complète
`docs/crypto.md` (comment les données sont chiffrées) avec le
raisonnement sur les métadonnées.

## 1. Avertissement — ce que ce projet NE garantit PAS

**Anonymous ne garantit pas l'anonymat réseau absolu.**

> ⚠ **Mode `[privacy] e2ee = false`** : si un administrateur active
> explicitement ce mode (désactivé par défaut), **les messages ne
> sont PAS chiffrés de bout en bout**. Le serveur reçoit le texte en
> clair pour pouvoir appliquer une modération réelle
> (`[moderation]`), et son administrateur peut donc potentiellement
> lire les messages. Ce mode doit toujours être annoncé clairement
> aux utilisateurs du serveur concerné (page d'accueil, README local).
> Ne l'activez que si c'est un compromis que vos utilisateurs
> connaissent et acceptent.

Même avec l'architecture décrite ici (mode par défaut, `e2ee = true`) :

- votre fournisseur d'accès, un réseau Wi-Fi public, ou toute
  personne en mesure d'observer le trafic réseau peut voir que vous
  vous connectez à une adresse IP donnée, à quel moment, et
  approximativement combien de données transitent — même si le
  contenu est chiffré (TLS *et* chiffrement applicatif) ;
- l'hébergeur de la machine qui fait tourner le serveur peut voir les
  connexions entrantes (IP source, ports, horaires) au niveau système
  d'exploitation, même si le processus Anonymous lui-même ne les
  journalise pas ;
- un reverse proxy placé devant le serveur (Caddy/Nginx/Traefik, voir
  `docs/https.md`) peut, selon sa propre configuration, journaliser
  des informations de connexion (c'est à l'administrateur du serveur
  de configurer son reverse proxy pour minimiser cela s'il le
  souhaite) ;
- rien n'empêche un autre participant du salon de partager en dehors
  d'Anonymous ce qu'il a lu (un salon chiffré protège contre le
  serveur, pas contre un participant malveillant).

Ce que ce projet garantit, c'est un **anonymat applicatif et
cryptographique** : le serveur, par conception, n'a ni les moyens ni
les données pour relier un message à une identité applicative
persistante. C'est un modèle de menace différent — et plus restreint
— qu'un outil d'anonymat réseau comme Tor. Les deux peuvent se
combiner (rien n'empêche de faire tourner un client Anonymous à
travers Tor), mais Anonymous seul ne fait pas ce travail.

## 2. Ce que le serveur reçoit, et pendant combien de temps

| Donnée                                   | Reçue ?         | Stockage             | Durée de vie |
|--------------------------------------------|-----------------|------------------------|--------------|
| Contenu en clair des messages               | Jamais          | —                      | —            |
| Clé de chiffrement des messages (epoch)     | Jamais          | —                      | —            |
| Secret de salon                             | Jamais          | —                      | —            |
| Clé privée Ed25519 de session                | Jamais          | —                      | —            |
| Clé **publique** Ed25519 de session          | Oui (nécessaire)| RAM uniquement         | Jusqu'à expiration de session ou redémarrage |
| `session_id`                                | Oui             | RAM uniquement         | Idem |
| `anonymous_number`                           | Généré par le serveur | SQLite (avec le message) | Permanent (suit la rétention des messages) — voir §3 |
| Ciphertext + métadonnées d'enveloppe          | Oui             | SQLite                | Selon la politique de rétention configurée |
| Adresse IP de connexion                      | Oui (TCP)       | RAM uniquement (compteurs de rate limiting) | Quelques minutes (fenêtre glissante), jamais écrite sur disque |
| Mot de passe serveur en clair                 | Oui, ponctuellement (login) | Jamais stocké — seul le hash Argon2id l'est, dans la config admin | Permanent (c'est un secret de configuration, pas une donnée utilisateur) |
| Jeton d'authentification serveur (`auth.py`) | Non — généré par le serveur | RAM uniquement | 6h par défaut |

## 3. Justification détaillée du schéma SQLite

### Table `messages`

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_type TEXT NOT NULL,       -- "msg" | "file" | "kx"
    protocol_version INTEGER NOT NULL,
    algorithm TEXT NOT NULL,           -- nom d'algorithme, pas une clé
    key_id TEXT NOT NULL,              -- "<room_id>.<epoch>", pas une identité
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,          -- opaque pour le serveur
    size_bytes INTEGER NOT NULL,       -- pour les quotas
    created_at REAL NOT NULL,          -- pour la rétention / l'ordre d'affichage
    anonymous_number INTEGER NOT NULL  -- voir ci-dessous
)
```

Chaque colonne a une fonction technique précise et aucune ne permet,
seule ou combinée aux autres, de reconstruire une identité réelle :

- `envelope_type`, `protocol_version`, `algorithm`, `nonce`,
  `ciphertext` : nécessaires pour que N'IMPORTE QUEL détenteur du
  secret de salon puisse déchiffrer — ce sont des paramètres de
  déchiffrement, pas des identifiants.
- `key_id` encode `<room_id>.<epoch>` : le `room_id` est un
  identifiant de SALON (partagé par tous ses membres), pas de client ;
  l'epoch est un compteur de rotation de clé, partagé par tous les
  membres actifs pendant cette période.
- `size_bytes`, `created_at` : nécessaires pour les quotas et la
  rétention automatique (voir `retention.py`).
- **`anonymous_number`** (exception documentée) : voir `docs/crypto.md`
  §9.4. C'est un pseudonyme de SESSION, tiré aléatoirement par le
  serveur à chaque nouvelle session (jamais choisi ni fourni par le
  client), qui ne peut être relié à aucune clé publique, IP, ou autre
  session passée/future une fois cette session expirée. Le stocker
  permet à l'historique d'être cohérent avec ce qui a été vu en
  direct ; cela ne crée pas de corrélation qui n'était pas déjà
  visible pendant la session elle-même.

Colonnes qui **n'existent pas et ne doivent jamais être ajoutées** :
`owner`, `owner_token_hash`, `client_token`, `user_id`, `client_id`,
`ip`, `username`, `session_id`, `public_key`. Un test automatisé
(`tests/test_server/test_server.py::test_privacy_schema_has_no_identity_columns`)
vérifie ceci à chaque exécution de la suite de tests.

### Table `files`

```sql
CREATE TABLE files (
    file_id TEXT PRIMARY KEY,  -- généré aléatoirement par le serveur
    size_bytes INTEGER NOT NULL,
    created_at REAL NOT NULL
)
```

Le nom de fichier réel, son type MIME, et son contenu ne sont
JAMAIS connus du serveur : ils sont chiffrés côté client dans les
métadonnées du message qui référence ce `file_id` (voir
`client/src/protocol.py::FileMetadataPayload`).

## 4. Sessions éphémères : pourquoi RAM et pas SQLite

Voir `server/src/session.py` et `docs/crypto.md` §9. Le choix de ne
JAMAIS persister le registre de sessions (ni sur disque, ni dans
SQLite) est délibéré :

- une session n'a de sens que pendant qu'un client est potentiellement
  actif ; la persister au-delà n'apporterait rien au protocole ;
- ne rien persister garantit mécaniquement qu'un redémarrage du
  serveur invalide toutes les sessions (testé explicitement : voir
  `test_server_restart_invalidates_sessions`) ;
- cela élimine par construction tout risque qu'une sauvegarde de base
  de données, un accès disque non autorisé, ou un outil d'inspection
  SQLite ne révèle une clé publique liée à un numéro de session.

## 5. Rate limiting et adresses IP : l'exception assumée

`server/src/ratelimit.py` utilise l'adresse IP de la connexion TCP
comme clé d'un compteur en mémoire, pour limiter les abus (spam de
messages, d'uploads, de créations de session) sans exiger de compte.
C'est la seule utilisation de l'IP dans tout le projet, et elle est
strictement encadrée :

- l'IP n'est **jamais écrite sur disque** ;
- l'IP n'est **jamais journalisée** (voir §6) ;
- l'IP n'est **jamais associée à un message stocké** — le compteur de
  rate limiting est un simple entier par IP, complètement séparé de
  la table `messages` ;
- le compteur est oublié dès l'expiration de sa fenêtre glissante
  (quelques dizaines de secondes à quelques minutes selon le
  paramètre) ou au redémarrage du serveur.

Deux connexions depuis la même IP (même réseau domestique, même VPN,
même NAT d'entreprise) partagent le même compteur : ce n'est pas une
identité applicative, seulement une mesure anti-abus au niveau
réseau, orthogonale à tout ce qui est stocké de façon persistante.

## 6. Logs — ce qui est journalisé et ce qui ne l'est jamais

Configuration par défaut (`[logging] access_logs = false`) : Uvicorn
ne journalise PAS les accès HTTP (qui contiendraient IP + route + code
de statut). Les seuls messages journalisés par l'application
elle-même sont volontairement génériques :

```
server started
database initialized
storage cleanup completed
websocket error
échec du passage de rétention
échec du nettoyage des sessions expirées
```

Aucun message de log ne contient : une adresse IP, un `session_id`,
une clé publique, un `client_token`, un contenu de message (chiffré
ou non), ou un nom de fichier. Un test automatisé
(`test_logs_never_contain_session_id_or_public_key`) le vérifie pour
le cas des sessions ; toute contribution future qui ajouterait un
`logger.info(...)` incluant une de ces valeurs serait une régression
de confidentialité.

Si vous déployez derrière un reverse proxy (Caddy/Nginx/Traefik), ce
proxy peut avoir ses PROPRES logs d'accès (souvent activés par
défaut). Ce projet ne peut pas contrôler cette couche : consultez
`docs/https.md` et la documentation de votre reverse proxy pour les
désactiver ou les minimiser si c'est votre objectif.

## 7. Anti-corrélation : ce qui a été activement évité

- Pas de structure `client_id -> messages[]`, même temporaire.
- Pas d'identifiant de connexion WebSocket persisté ou journalisé
  (`_active_sockets` est une simple liste technique pour la diffusion,
  jamais reliée à un message stocké).
- Pas de cookie de session HTTP.
- Le jeton d'authentification serveur (`auth.py`) est un secret
  opaque, généré aléatoirement, sans lien avec une session de
  signature (§9 de `docs/crypto.md`) ni avec un `anonymous_number` :
  connaître l'un ne donne aucune information sur l'autre.
- Les fichiers sont stockés sous des noms générés aléatoirement par le
  serveur (`storage.py::FileStorage._new_file_id`), jamais sous le nom
  fourni par le client (qui de toute façon ne voit jamais ce nom en
  clair, voir `docs/crypto.md` §6).

## 8. Ce qu'un audit externe devrait vérifier

Si vous auditez un déploiement Anonymous, voici où regarder :

1. `PRAGMA table_info(messages)` et `PRAGMA table_info(files)` — la
   liste de colonnes doit correspondre exactement à celle documentée
   en §3, rien de plus.
2. Les logs du service (`journalctl -u anonymous-server` ou
   équivalent) — aucune IP, aucune clé, aucun `session_id`.
3. Le contenu du dossier de stockage de fichiers — uniquement des noms
   aléatoires opaques, aucune métadonnée de nom de fichier original.
4. `server.toml` — `auth.password_hash` doit être un hash Argon2id
   (`$argon2id$...`), jamais un mot de passe en clair.
5. Le code source de `session.py` — confirmer qu'aucune fonction n'y
   écrit sur disque ni ne journalise.
