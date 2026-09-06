# Architecture — docs/architecture.md

## 1. Vue d'ensemble

Anonymous est composé de deux binaires **totalement indépendants** :

```
anonymous            (client terminal, curses)
anonymous-server     (serveur FastAPI/WebSocket/SQLite)
```

N'importe qui peut héberger son propre `anonymous-server` — sur un
Raspberry Pi, une VM, un serveur dédié — et en partager l'adresse
(`http://mon-serveur:8000` ou `https://chat.example.org`) avec qui il
veut. Il n'existe **aucun serveur central**, aucun registre, aucune
fédération obligatoire entre serveurs.

```
                     INTERNET
                         |
                +--------+--------+
                | Anonymous Server |
                |                  |
                | FastAPI          |
                | WebSocket        |
                | SQLite           |
                | Stockage fichiers|
                +--------+---------+
                         |
              ciphertext uniquement
                         |
          +--------------+--------------+
          |                             |
       Client A                      Client B
          |                             |
       chiffre                      déchiffre
          |                             |
       terminal                      terminal
```

Chaque serveur est totalement autonome (voir §5). Un client peut se
connecter à autant de serveurs qu'il veut, l'un après l'autre
(`/connect`), et gérer plusieurs salons (`/room`) indépendamment des
serveurs auxquels il se connecte.

## 2. Le serveur : un relais aveugle

Le serveur ne fait que :

- recevoir des enveloppes chiffrées opaques (`POST /messages`) ;
- vérifier qu'elles proviennent d'une session valide (signature
  Ed25519, voir `docs/crypto.md` §9) — sans jamais apprendre qui est
  derrière cette session ;
- les stocker (SQLite) selon les quotas et la politique de rétention
  configurés par l'administrateur ;
- les diffuser aux clients connectés (WebSocket) ;
- stocker et servir des fichiers chiffrés opaques ;
- appliquer des limites de débit (anti-abus) sans construire de
  compte utilisateur.

Il ne peut PAS :

- déchiffrer un message ou un fichier (il n'a jamais les clés) ;
- attribuer un message à une identité réelle ou applicative
  persistante ;
- restaurer une session après son propre redémarrage.

## 3. Le client : aussi stateless que possible

Le client terminal maintient localement :

- ses salons connus (`~/.local/share/anonymous/rooms.json`,
  permissions `0600`) — la seule chose vraiment persistée ;
- éventuellement une liste de serveurs favoris ;
- un dossier de téléchargement pour les fichiers reçus.

Ce qu'il NE persiste PAS :
- sa clé de signature Ed25519 de session (régénérée à chaque
  `/connect`, voir `docs/crypto.md` §9) ;
- un quelconque historique de messages en dehors de ce que le serveur
  lui renvoie sur demande ;
- une quelconque base de données utilisateur.

## 4. Composants (arborescence du projet)

```
anonymous/
├── assets/
├── client/src/
│   ├── main.py       — interface curses, commandes, réseau
│   ├── config.py      — préférences locales (pas de secrets)
│   ├── crypto.py       — protocole crypto (voir docs/crypto.md)
│   ├── protocol.py     — structures de contenu en clair + constantes réseau
│   ├── media.py        — chiffrement de fichiers par blocs
│   ├── framing.py       — framing binaire longueur-préfixée
│   └── storage.py       — stockage local des secrets (XDG, permissions)
├── server/
│   ├── src/
│   │   ├── main.py       — application FastAPI
│   │   ├── config.py      — chargement/validation de server.toml
│   │   ├── database.py     — accès SQLite (schéma minimal)
│   │   ├── storage.py       — fichiers chiffrés (quotas, anti path-traversal)
│   │   ├── retention.py      — suppression automatique (âge/quantité)
│   │   ├── auth.py            — mot de passe serveur (Argon2id) + jetons temporaires
│   │   ├── session.py          — sessions éphémères de signature (RAM uniquement)
│   │   ├── ratelimit.py         — limitation de débit en mémoire
│   │   └── protocol.py           — validation des enveloppes (Pydantic)
│   ├── systemd/anonymous-server.service
│   └── debian/{postinst,prerm}
├── docs/
│   ├── crypto.md      — protocole cryptographique complet
│   ├── privacy.md      — modèle de menace, justification des données
│   ├── architecture.md  — ce document
│   ├── server.md         — installation/exploitation du serveur
│   └── https.md           — reverse proxy (Caddy/Nginx/Traefik)
├── tests/
├── build.sh
├── meb.toml            — paquet .deb du client
├── meb-server.toml      — paquet .deb du serveur
├── pyproject.toml
└── README.md
```

## 5. Autonomie des serveurs — pas de fédération

Chaque serveur fonctionne complètement seul :

```
Server A            Server B            Server C
   |                    |                    |
   + clients            + clients            + clients
```

Il n'existe, dans cette version, **aucun mécanisme obligeant deux
serveurs à communiquer entre eux** : pas de fédération, pas de
registre partagé, pas de protocole peer-to-peer entre serveurs, pas de
blockchain. Un client qui veut parler à des personnes sur deux
serveurs différents doit s'y connecter séparément (`/connect` sur
chacun, éventuellement avec des salons différents ou le même secret de
salon partagé manuellement sur les deux). Une éventuelle découverte ou
relais serveur-à-serveur pourrait être ajoutée dans une future version
comme protocole séparé et strictement optionnel — ce n'est pas prévu
ici.

## 6. Basse consommation

Le serveur ne dépend d'aucun service externe obligatoire :

- **SQLite** (fichier local) plutôt que PostgreSQL ;
- **une tâche asyncio périodique légère** (rétention + nettoyage des
  sessions, toutes les 60 secondes) plutôt que Celery/Redis/Kafka ;
- **des structures en mémoire** (dictionnaires, compteurs) pour le
  rate limiting et les sessions, plutôt qu'un service de cache externe ;
- **un seul processus Uvicorn** (pas de pool de workers imposé — voir
  `docs/server.md` si vous voulez néanmoins scaler horizontalement,
  avec les limites que cela implique pour l'état en mémoire).

Une petite machine (Raspberry Pi, VPS d'entrée de gamme) suffit à faire
tourner un serveur Anonymous pour un groupe de taille raisonnable.
