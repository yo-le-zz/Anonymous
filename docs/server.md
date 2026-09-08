# Exploiter un serveur Anonymous — docs/server.md

## 1. Installation via le paquet `.deb`

```bash
sudo apt install ./anonymous-server_1.0.1_amd64.deb
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
