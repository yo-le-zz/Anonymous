# Exploiter un serveur Anonymous — docs/server.md

## 1. Installation via le paquet `.deb`

```bash
sudo apt install ./anonymous-server_1.0.4_amd64.deb
```

Ceci installe :

```
/usr/bin/anonymous-server
/etc/anonymous/server.toml       (configuration, exemple commenté)
/var/lib/anonymous/               (base SQLite + fichiers chiffrés)
/var/log/anonymous/                (si votre journalisation système l'utilise)
/etc/systemd/system/anonymous-server.service
```

avec un utilisateur système dédié `anonymous` (créé par le script
`postinst`, voir §6), propriétaire de `/var/lib/anonymous` et
`/var/log/anonymous` uniquement — jamais root.

## 2. Démarrage

```bash
sudo systemctl enable --now anonymous-server
sudo systemctl status anonymous-server
```

Le service démarre automatiquement au boot et redémarre après un
crash (`Restart=on-failure` dans l'unité systemd, voir §6).

## 3. Configuration (`/etc/anonymous/server.toml`)

Toutes les valeurs sont validées au démarrage (`server/src/config.py`)
— une configuration invalide fait échouer le démarrage avec un message
clair plutôt que de tourner dans un état incohérent.

```toml
[server]
host = "127.0.0.1"     # écoute en local ; utilisez un reverse proxy
port = 8000             # pour exposer publiquement, voir docs/https.md

[network]
public_url = ""          # informatif seulement, ex: "https://chat.example.org"

[auth]
enabled = false
password_hash = ""        # généré par `anonymous-server hash-password`

[storage]
database = "/var/lib/anonymous/chat.db"
files = "/var/lib/anonymous/files"
max_storage_bytes = 1073741824   # 1 Go

[messages]
max_size = 10000           # octets de ciphertext max par message
max_messages = 10000         # au-delà, les plus anciens sont supprimés

[retention]
enabled = true
max_age_seconds = 0            # 0 = pas de limite d'âge
delete_oldest = true             # supprime les plus anciens si max_messages dépassé

[files]
enabled = true
max_file_size = 52428800          # 50 Mo
max_files_per_message = 5
allowed_types = [
    "image/jpeg", "image/png", "image/webp",
    "video/mp4", "video/webm", "application/pdf",
]

[crypto]
key_rotation_messages = 100        # indicatif — la rotation réelle est décidée côté client
key_rotation_seconds = 3600

[session]
ttl_seconds = 21600                  # durée de vie d'une session éphémère (6h)

[logging]
access_logs = false

[ratelimit]
messages_per_minute = 30
uploads_per_minute = 10
sessions_per_minute = 20
max_connections_per_ip = 20
```

Après modification, redémarrez le service :

```bash
sudo systemctl restart anonymous-server
```

## 4. Mot de passe serveur (optionnel)

Pour protéger l'accès (pas l'identité — voir `docs/crypto.md` §9) :

```bash
sudo -u anonymous anonymous-server hash-password
```

La commande demande le mot de passe (deux fois, sans l'afficher) et
affiche le bloc TOML à coller dans `server.toml` :

```toml
[auth]
enabled = true
password_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
```

Le mot de passe en clair n'est jamais stocké. Il sert uniquement à
autoriser l'usage du serveur (`/auth/login` renvoie un jeton temporaire
en mémoire, voir `docs/crypto.md`) — il ne devient jamais un nom
d'utilisateur, n'est jamais lié à un message, et n'est jamais utilisé
pour chiffrer quoi que ce soit.

## 5. Rétention et messages éphémères

```toml
[retention]
enabled = true
max_age_seconds = 86400   # supprime tout message de plus de 24h
delete_oldest = true       # ET applique aussi la limite de quantité (messages.max_messages)
```

Le nettoyage tourne toutes les 60 secondes (tâche asyncio légère,
intégrée au processus serveur — pas de worker ni de service externe).
Un message envoyé est **immuable** : il ne peut être supprimé que par
cette politique de rétention automatique, jamais par un client
(pas de `/edit`, pas de `/delete`).

## 6. Détails du paquet `.deb` et du service systemd

`server/systemd/anonymous-server.service` (extrait) :

```ini
[Service]
User=anonymous
Group=anonymous
ExecStart=/usr/bin/anonymous-server
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/anonymous /var/log/anonymous
```

`ProtectSystem=strict` rend tout le système de fichiers en lecture
seule pour le processus SAUF les chemins listés explicitement dans
`ReadWritePaths` : le service ne peut écrire que dans
`/var/lib/anonymous` (base + fichiers) et `/var/log/anonymous`. Les
scripts `postinst`/`prerm` du paquet créent/suppriment l'utilisateur
système `anonymous` et posent les permissions (`0700` sur
`/var/lib/anonymous`, propriétaire `anonymous:anonymous`).

## 7. Vérifier qu'un déploiement respecte le modèle de confidentialité

Voir `docs/privacy.md` §8 pour la liste de vérifications (schéma
SQLite, logs, stockage de fichiers, configuration d'authentification).

## 8. Domaine et exposition publique

Pour exposer votre serveur sur un nom de domaine avec HTTPS, voir
`docs/https.md` — le serveur Anonymous lui-même n'a pas besoin de
gérer TLS directement ; il écoute en HTTP local (`127.0.0.1:8000` par
défaut) et laisse un reverse proxy (Caddy, Nginx, ou Traefik)
s'occuper du certificat et de l'exposition publique.

## 9. Ligne de commande complète

```bash
anonymous-server                              démarre le serveur (usage systemd normal)
anonymous-server --version                    affiche la version et quitte
anonymous-server --help                       aide complète
anonymous-server --config /chemin/vers.toml   utilise ce fichier au lieu du défaut
anonymous-server hash-password                 génère le hash Argon2id du mot de passe serveur
anonymous-server generate-admin-password-hash  génère le hash Argon2id du mot de passe admin
anonymous-server check-config                  valide server.toml et quitte (sans démarrer)
anonymous-server stats                         affiche les statistiques agrégées et quitte
anonymous-server cleanup                       exécute un passage de rétention immédiat et quitte
anonymous-server reload                        envoie un signal de rechargement au serveur déjà lancé
anonymous-server config                        assistant de configuration interactif (TUI)
```

`--version` et `check-config` fonctionnent même si `server.toml` est
actuellement invalide (ils le signalent proprement au lieu de
planter) — pratique pour diagnostiquer un déploiement cassé.

### Assistant de configuration (`anonymous-server config`)

Ouvre un écran interactif : flèches haut/bas pour naviguer, Entrée
pour modifier un champ (avec sa description affichée en bas d'écran),
`s` pour enregistrer, `q`/Échap pour quitter sans rien changer. Aucune
navigation forcée : on peut revenir sur n'importe quel champ à tout
moment avant d'enregistrer. Les réglages non montrés par l'assistant
(cas avancés) ne sont jamais modifiés ni perdus.

## 10. Rechargement à chaud et revérification automatique

`server.toml` est revérifié automatiquement toutes les ~60 secondes
par le serveur lui-même (piggyback sur la tâche de rétention, pas de
worker supplémentaire) : si le fichier a changé sur disque, les
sections sûres sont appliquées sans redémarrage —

```
messages, retention, files, rooms, ratelimit,
features, privacy, moderation, web, logging
```

Tout le reste (`server`, `storage`, `session`, `auth`, `crypto`,
`network`) nécessite un vrai redémarrage : les changer à chaud
créerait un état incohérent (port déjà lié, base déjà ouverte, jetons
déjà émis...).

Trois façons équivalentes de forcer un rechargement immédiat sans
attendre le prochain passage automatique :

```bash
sudo systemctl reload anonymous-server     # via systemd (ExecReload)
anonymous-server reload                     # via le fichier PID local
kill -HUP <pid>                              # signal direct
```

Une session admin peut aussi le déclencher à distance via
`POST /admin/reload` (voir docs/crypto.md §10). Dans tous les cas, un
fichier devenu invalide entre-temps est **ignoré** : l'ancienne
configuration valide continue de tourner, avec un message clair dans
les logs.

## 11. Serveur temporaire

Pour un chat jetable (durée de vie fixée à l'avance) :

```toml
[temporary]
enabled = true
lifetime_seconds = 3600   # 1 heure
```

À l'expiration, le serveur purge **tous** ses messages et fichiers
puis s'éteint proprement. La vérification suit la même cadence que la
rétention (~60 secondes) : la durée de vie réelle peut donc dépasser
légèrement `lifetime_seconds` de quelques dizaines de secondes.

## 12. Docker

Alternative au paquet `.deb`, pour n'importe quel système :

```bash
docker compose up -d
```

ou manuellement :

```bash
docker build -f server/Dockerfile -t anonymous-server .
docker run -p 8000:8000 -v anonymous-data:/data anonymous-server
```

Au premier lancement, une configuration par défaut est générée dans
le volume (`/data/server.toml`, adaptée aux chemins du conteneur) si
aucune n'existe déjà — modifiez-la puis redémarrez le conteneur
(ou utilisez `anonymous-server reload` à l'intérieur du conteneur).
Une image est publiée sur `ghcr.io` à chaque tag de version (voir
`.github/workflows/release.yml`).

## 13. Page web publique, statut et statistiques

- `GET /` — page HTML publique (activable/désactivable et
  personnalisable via `[web]`), aucune ressource externe, aucun
  tracking.
- `GET /status` — texte brut orienté supervision (version, salons, en
  ligne, stockage, uptime) — jamais d'IP, de chemin filesystem, de PID
  ou de variable d'environnement.
- `GET /api/stats` — JSON agrégé (`online`, `rooms`, `messages`,
  `storage_bytes`), jamais de liste d'identifiants individuels.
- `GET /policy` — politique de modération publique, pour un filtrage
  indicatif côté client (voir docs/crypto.md §11-12).
