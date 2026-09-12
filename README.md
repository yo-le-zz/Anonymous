# Anonymous

Anonymous est un chat en groupe **chiffré de bout en bout**, **sans
compte**, **sans serveur central**, dont le serveur ne peut par
conception ni lire les messages ni les attribuer à une identité
applicative permanente.

> ⚠ **Anonymous ne garantit pas l'anonymat réseau absolu.** Votre
> fournisseur d'accès, un reverse proxy, ou votre hébergeur peuvent
> observer des métadonnées de connexion (IP, horaires, volumétrie),
> même si le contenu de vos messages reste chiffré de bout en bout.
> Voir `docs/privacy.md` pour le modèle de menace complet.

## En bref

- **Chiffrement de bout en bout** : X25519 + HKDF-SHA256 + AES-256-GCM
  / ChaCha20-Poly1305, avec rotation régulière des clés (voir
  `docs/crypto.md`).
- **Identité de session éphémère** : chaque connexion affiche un
  numéro temporaire (`Anonymous #583921`), attribué par le serveur,
  jamais un compte — nouveau à chaque connexion, invalidé au
  redémarrage du serveur, protégé contre l'usurpation par signature
  Ed25519.
- **Salons (rooms)** : canaux publics ou protégés par mot de passe
  côté serveur, `/room list` pour les découvrir, indépendants du
  secret de chiffrement de bout en bout.
- **Aucun serveur central** : n'importe qui installe et héberge son
  propre serveur, puis en partage l'adresse.
- **Fichiers chiffrés côté client** avant envoi (images, vidéos,
  documents), noms de fichiers protégés côté serveur.
- **Basse consommation** : SQLite, pas de Redis/Celery/PostgreSQL,
  une seule tâche périodique légère pour la rétention.
- **Messages éphémères configurables** (par âge ou par quantité).
- **Réactions et réponses** chiffrées, **pseudos locaux** avec couleur
  (jamais envoyés au serveur), **indicateurs de frappe** en direct.
- **Administration sans identité** : un rôle admin ponctuel (premier
  arrivé ou mot de passe partagé), jamais exposé aux autres clients,
  pour recharger la config ou gérer les salons — voir `docs/crypto.md`.
- **Anti-spam progressif**, **page web publique** sans tracking
  (`/`, `/status`, `/api/stats`), **serveur temporaire** auto-destructeur.
- **Assistant de configuration visuel** (`anonymous-server config`) et
  CLI classique (`--version`, `stats`, `check-config`...).
- **Docker** (`docker compose up -d`) en plus du paquet `.deb`.
- **Binaires officiels** pour Linux et Windows publiés automatiquement
  à chaque tag de version (voir `.github/workflows/release.yml`).

## Installation

### Client

```bash
sudo apt install ./anonymous_1.0.4_amd64.deb
anonymous
```

### Serveur

```bash
sudo apt install ./anonymous-server_1.0.4_amd64.deb
sudo systemctl enable --now anonymous-server
```

Ou via Docker :

```bash
docker compose up -d
```

Sous Windows, téléchargez `anonymous-windows-amd64.zip` /
`anonymous-server-windows-amd64.zip` depuis la page
[Releases](../../releases) et lancez l'exécutable directement (aucune
installation requise).

Voir `docs/server.md` pour la configuration complète
(`/etc/anonymous/server.toml`), le mot de passe serveur, la rétention,
et le durcissement systemd.

## Salons (rooms)

Chaque message appartient à un salon (canal), un simple espace de
nommage côté serveur — pas une identité. Un salon peut être public
(créé librement, sans mot de passe) ou protégé par un mot de passe de
salon (distinct du secret de chiffrement de bout en bout) :

```
/room list                       liste les salons connus + ceux du serveur connecté
/room new général                crée/rejoint un salon public
/room new prive monmotdepasse     crée un salon protégé par mot de passe
/room password prive monmotdepasse   mémorise le mot de passe pour /connect ultérieurs
```

Voir `docs/crypto.md` pour la distinction entre le mot de passe de
salon (contrôle d'accès côté serveur) et le secret de chiffrement de
bout en bout (toujours partagé hors bande entre clients).

## Démarrage rapide

```
/connect http://mon-serveur:8000
/room new mon-salon
```

Le client affiche l'invitation à partager **hors bande** (jamais via
le chat lui-même) avec les personnes que vous voulez inviter :

```
anon1:xxxxxxxx:yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

Sur un autre poste :

```
/connect http://mon-serveur:8000
/room join anon1:xxxxxxxx:yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy mon-salon
```

Vous pouvez aussi établir un salon sans jamais faire transiter le
secret lui-même, via un échange Diffie-Hellman X25519 :
`/room exchange start` (voir `docs/crypto.md` §3.2).

## Commandes du client

```
/help                          liste des commandes
/connect URL [mot_de_passe]     se connecter à un serveur
/disconnect                     se déconnecter
/server                         état de connexion (serveur, salon, identité)
/room new|join|use|list|password    gérer les salons
/room exchange start|respond|finish   échange de secret par X25519
/upload chemin                  envoyer un fichier chiffré
/download id                    télécharger un fichier reçu
/react id emoji                 réagir à un message
/reply id texte                 répondre à un message
/nick numéro nom [couleur]      pseudo local (jamais envoyé au serveur)
/admin claim|reload|room-password   administration éphémère
/quit                           quitter
texte + Entrée                  envoyer un message
```

Aucune commande `/edit` ni `/delete` : un message envoyé est
immuable ; seule la rétention automatique configurée par
l'administrateur du serveur peut supprimer d'anciens messages.

## Documentation

| Document | Contenu |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Vue d'ensemble, composants, autonomie des serveurs |
| [`docs/crypto.md`](docs/crypto.md) | Protocole cryptographique complet (chiffrement + session/signature) |
| [`docs/privacy.md`](docs/privacy.md) | Modèle de menace, justification de chaque donnée conservée |
| [`docs/server.md`](docs/server.md) | Installation, configuration, systemd, mot de passe, rétention |
| [`docs/https.md`](docs/https.md) | Exposition publique via Caddy / Nginx / Traefik |

## Modèle de menace en un paragraphe

Le serveur reçoit et stocke des enveloppes chiffrées opaques qu'il ne
peut pas déchiffrer, ne connaît jamais les clés privées des clients,
et n'a aucun mécanisme pour relier un message à une identité
applicative persistante. Une session (numéro affiché
"Anonymous #XXXXXX") est un pseudonyme purement temporaire, vérifié
par signature Ed25519 pour empêcher l'usurpation, vivant uniquement en
mémoire et disparaissant à l'expiration ou au redémarrage du serveur.
Ce que ce modèle NE couvre PAS : l'anonymat au niveau réseau
(métadonnées de connexion visibles par l'hébergeur, le réseau, ou un
reverse proxy) et la confidentialité persistante par message façon
Signal/MLS. Détails complets dans `docs/crypto.md` et
`docs/privacy.md`.

## Limites de l'anonymat

- Le serveur voit les adresses IP qui s'y connectent (au niveau TCP),
  utilisées uniquement en mémoire pour la limitation de débit anti-abus,
  jamais journalisées ni stockées avec un message.
- Un reverse proxy placé devant le serveur peut avoir ses propres logs
  d'accès, indépendants de ce que fait Anonymous lui-même.
- Un participant du salon peut toujours partager en dehors d'Anonymous
  ce qu'il y a lu — le chiffrement protège contre le serveur, pas
  contre les autres membres du salon.
- Ce projet **ne fait pas** office d'outil d'anonymat réseau comme Tor
  ; il peut être combiné avec un tel outil si c'est votre besoin.

## Développement

```bash
uv sync --group dev
uv run pytest tests -v
```

Construire les binaires et paquets `.deb` (Linux) :

```bash
./build.sh
```

nécessite [`uv`](https://github.com/astral-sh/uv), `dpkg-dev` et
`patchelf` (`sudo apt install dpkg-dev patchelf`). Aucune dépendance à
un outil tiers de packaging : Nuitka compile les binaires, `dpkg-deb`
assemble les `.deb` directement.

Pour Windows, les exécutables `.exe` sont produits par
`.github/workflows/release.yml` sur un runner Windows natif (Nuitka
doit compiler sur l'OS cible).

## Intégration continue et releases

- **CI** (`.github/workflows/ci.yml`) : suite de tests complète sur
  Linux et Windows à chaque push/pull request, plus une vérification
  indépendante du schéma SQLite réel (pas un grep heuristique).
- **Release** (`.github/workflows/release.yml`) : à chaque tag
  `vX.Y.Z` poussé sur GitHub, build automatique des binaires et
  paquets pour Linux (`.deb` + `.tar.gz`) et Windows (`.zip`), publiés
  directement sur la page GitHub Release correspondante.

```bash
git tag v1.0.4
git push origin v1.0.4
```

## Rotation des clés et rétention (aperçu)

```toml
[crypto]
key_rotation_messages = 100
key_rotation_seconds = 3600

[retention]
enabled = true
max_age_seconds = 86400   # 0 = illimité
delete_oldest = true
```

Détails complets : `docs/crypto.md` (rotation) et `docs/server.md`
(rétention, quotas, fichiers).

## Licence et contributions

Projet communautaire — voir les fichiers sous `docs/` avant toute
contribution touchant à la cryptographie ou au stockage : toute
modification qui réintroduirait une identité persistante, un
`client_token`, ou un mapping utilisateur → messages sera refusée.
