# Anonymous Crypto Protocol v1

Ce document décrit précisément le protocole cryptographique utilisé
par Anonymous. Il est volontairement simple : chaque décision est
justifiée, et les limites sont documentées honnêtement plutôt que
maquillées.

Toutes les primitives viennent de la bibliothèque
[`cryptography`](https://cryptography.io/) (implémentation OpenSSL).
Aucune primitive cryptographique n'est réimplémentée par ce projet.

## 1. Vue d'ensemble

Anonymous chiffre les messages **de bout en bout entre clients qui
partagent un même secret de salon**. Le serveur relaie et stocke des
enveloppes opaques qu'il ne peut pas déchiffrer.

```
Client A                     Serveur                     Client B
   |                            |                            |
   | -- POST /messages -------> |                            |
   |    (enveloppe chiffrée)    | -- stocke, diffuse -------> |
   |                            |    (WebSocket)              |
   |                            |                            |
   |                            |                    déchiffre localement
```

Il n'y a **pas** de serveur d'identité, **pas** de répertoire de clés
publiques par utilisateur, et **pas** de compte. Ce que le protocole
fournit :

- confidentialité et intégrité des messages pour quiconque possède le
  secret du salon ;
- rotation régulière des clés de chiffrement (limite l'impact d'une
  compromission ponctuelle) ;
- un mécanisme optionnel pour établir un secret de salon entre deux
  personnes sans jamais faire transiter ce secret en clair.

Ce que le protocole **ne fournit pas** (limites assumées, voir aussi
`docs/privacy.md`) :

- pas de ratchet asynchrone par message façon Signal/MLS (le retrait
  d'un participant du salon ne fait pas « oublier » les messages
  passés tant que le secret de salon n'est pas changé — un participant
  révoqué qui a gardé le secret peut toujours déchiffrer les messages
  qu'il recevra tant que le secret n'a pas été renouvelé) ;
- pas de vérification d'identité des participants (n'importe qui
  possédant le secret de salon peut écrire et lire) ;
- pas d'anonymat réseau : voir l'avertissement en tête du README.

## 2. Primitives

| Rôle                                   | Primitive                          |
|-----------------------------------------|-------------------------------------|
| Établissement de secret (invitation)    | X25519 (ECDH)                       |
| Dérivation de clé                       | HKDF-SHA256                         |
| Chiffrement authentifié des messages    | AES-256-GCM **ou** ChaCha20-Poly1305 |
| Génération d'aléa                       | `secrets.token_bytes` / `os.urandom` (via `cryptography`) |

Le choix entre AES-256-GCM et ChaCha20-Poly1305 est fait par
l'expéditeur et indiqué en clair dans l'enveloppe (`algorithm`) : les
deux sont des chiffrements authentifiés éprouvés, le second étant
préférable sur du matériel sans accélération AES.

## 3. Secret de salon (Room)

Un salon (« Room ») est défini par :

- `room_id` : 8 octets aléatoires, non secrets, servent uniquement à
  distinguer les invitations et à préfixer les identifiants de clé.
  **Jamais envoyé au serveur.**
- `secret` : 32 octets aléatoires (`secrets.token_bytes(32)`).
  **Jamais envoyé au serveur, jamais stocké ailleurs que dans le
  dossier local du client (permissions `0600`).**

Une invitation (`Room.to_invite()`) est la chaîne :

```
anon1:<base64url(room_id)>:<base64url(secret)>
```

Elle doit être transmise **hors bande** (message chiffré existant,
rencontre physique, QR code, etc.) — jamais via le serveur Anonymous
lui-même.

### 3.1. Création directe

`/room new` génère un secret aléatoire localement. Simple, mais
suppose un canal de confiance pour transmettre l'invitation.

### 3.2. Établissement par échange X25519 (`/room exchange`)

Pour établir un secret de salon **sans jamais faire transiter le
secret lui-même**, même sur un canal non fiable, Anonymous propose un
échange Diffie-Hellman sur courbe X25519 :

1. **A** génère une paire de clés éphémère X25519 `(a_priv, a_pub)` et
   un `exchange_id` aléatoire (8 octets). Il transmet
   `exchange_id:a_pub` à **B** par un canal quelconque (peut être
   public/observé, ce n'est pas secret).
2. **B** génère sa propre paire éphémère `(b_priv, b_pub)`, calcule
   `shared = ECDH(b_priv, a_pub)`, et renvoie `exchange_id:b_pub` à
   **A**.
3. **A** calcule `shared = ECDH(a_priv, b_pub)`.
4. Les deux parties obtiennent le même `shared` car X25519 est
   commutatif : `ECDH(a_priv, b_pub) == ECDH(b_priv, a_pub)`.
5. Le secret de salon est dérivé :
   `room_secret = HKDF-SHA256(ikm=shared, salt=exchange_id, info="anonymous-chat-v1|room-secret", length=32)`.

**Limite documentée** : sans vérification indépendante, un relais
actif sur le canal de transmission des clés publiques (`a_pub`,
`b_pub`) pourrait mener une attaque de l'homme du milieu (substituer
sa propre clé aux deux parties). Anonymous fournit une **empreinte
courte** (`Room.fingerprint()`, SHA-256 tronqué du salon obtenu) que
les deux parties doivent comparer par un second canal (voix, message
déjà de confiance) avant de considérer l'échange comme fiable. C'est
la même logique que les « numéros de sécurité » de Signal/WhatsApp.

## 4. Rotation des clés par epoch

Le secret de salon n'est **jamais utilisé directement** pour chiffrer
des messages. Chaque *epoch* (un entier qui s'incrémente) a sa propre
clé :

```
epoch_key(n) = HKDF-SHA256(
    ikm  = room_secret,
    salt = room_id,
    info = "anonymous-chat-v1|epoch-key|" + str(n),
    length = 32,
)
```

L'epoch avance localement, indépendamment chez chaque client, selon
la politique de rotation :

```toml
[crypto]
key_rotation_messages = 100    # après 100 messages envoyés par CE client
key_rotation_seconds  = 3600   # ou après 1h, selon ce qui arrive en premier
```

Le numéro d'epoch utilisé pour chiffrer un message est inclus en clair
dans son `key_id` (`<room_id_b64>.<epoch>`), ce qui permet à
n'importe quel destinataire connaissant le secret de salon de
re-dériver la bonne clé et de déchiffrer — y compris s'il a manqué
des messages ou rejoint en retard.

**Limite documentée** : la rotation d'epoch limite la fenêtre de
compromission (si une clé d'epoch fuit, seuls les messages de cet
epoch sont exposés) mais ne fournit pas de confidentialité persistante
au sens strict : toutes les clés d'epoch sont dérivables tant que le
`room_secret` est connu. Un client peut choisir de purger de sa
mémoire les clés d'epochs révolues (`EpochKeyring.forget_before`) pour
réduire — pas éliminer — l'exposition en cas de compromission du
processus client après coup.

## 5. Format d'enveloppe (ce que voit le serveur)

```json
{
  "protocol_version": 1,
  "type": "msg",
  "algorithm": "AES-256-GCM",
  "key_id": "R25HUHpnOGR1N0k.3",
  "nonce": "base64url...",
  "ciphertext": "base64url..."
}
```

- `protocol_version` : entier, permet l'évolution future du format.
- `type` : `"msg"` (message texte), `"file"` (métadonnées de fichier
  chiffrées), ou `"kx"` (réservé, non utilisé par le serveur —
  l'échange X25519 actuel se fait entièrement hors bande côté client,
  ce type est prévu pour une future variante relayée par le serveur).
- `key_id` : `<room_id>.<epoch>` — identifie QUELLE clé re-dériver,
  jamais QUI a écrit.
- `nonce` : 96 bits aléatoires, un par message, jamais réutilisé avec
  la même clé (la rotation d'epoch limite drastiquement le nombre de
  messages par clé, rendant une collision de nonce astronomiquement
  improbable même sur la durée de vie d'un salon très actif).
- `ciphertext` : sortie AEAD (inclut le tag d'authentification).

Les données associées authentifiées (AAD) de chaque message sont
`"{protocol_version}|{algorithm}|{type}"` : cela empêche un serveur
malveillant de faire passer un message d'un type pour un autre ou de
rejouer un ciphertext sous une version de protocole différente sans
faire échouer la vérification GCM/Poly1305.

## 6. Fichiers

Voir directement les commentaires de `client/src/media.py`. Résumé :

- fichier découpé en blocs de 1 Mo ;
- chaque bloc chiffré indépendamment avec une clé dérivée du secret
  d'epoch (`derive_file_key`) et un nonce `base_nonce(8o) || compteur(4o)` ;
- AAD de chaque bloc = son index (empêche réordonnancement silencieux) ;
- le nombre total de blocs est inclus dans les métadonnées chiffrées
  du fichier, ce qui permet de détecter une troncature après lecture
  complète (limite documentée : une troncature n'est détectée qu'à la
  fin, pas bloc par bloc en flux — voir le commentaire de
  `media.py` pour le détail et la comparaison avec un vrai STREAM
  authentifié).

## 7. Ce que le serveur ne reçoit jamais

- le secret de salon, sous quelque forme que ce soit ;
- les clés privées X25519 générées lors d'un échange ;
- les clés privées Ed25519 de session (voir §9) ;
- les clés d'epoch ;
- le contenu en clair des messages ou des fichiers ;
- le nom de fichier ou son type MIME en clair (chiffrés dans les
  métadonnées) ;
- une quelconque identité applicative permanente (voir `docs/privacy.md`).

Nuance sur la clé publique Ed25519 de session (§9) : le serveur la
reçoit forcément (c'est nécessaire pour vérifier les signatures), mais
uniquement en RAM, liée à un `session_id` éphémère, jamais écrite sur
disque ni journalisée, et oubliée à l'expiration de la session ou au
redémarrage du serveur.

## 8. Que faire si vous n'êtes pas sûr·e

Ce protocole est adapté à un salon de discussion de groupe où la
confiance repose sur le partage du secret. Il **n'est pas** un
remplacement pour un protocole de messagerie asynchrone à ratchet
complet (Signal/MLS) si votre modèle de menace exige une révocation
fine par participant ou une confidentialité persistante par message.
Si c'est votre besoin, ce projet documente honnêtement cette limite
plutôt que de prétendre la couvrir.

---

## 9. Session éphémère et signature (Anonymous Protocol v2)

Cette section documente une extension ajoutée après la version
initiale du protocole (toujours `protocol_version: 1` pour le format
des enveloppes chiffrées — rien ne change dans la façon dont les
messages sont chiffrés). Ce qui est nouveau, c'est un mécanisme
séparé de **session éphémère signée**, qui permet d'afficher une
identité visuelle temporaire ("Anonymous #583921") sans jamais créer
de compte ni d'identité permanente.

### 9.1. Pourquoi une 4ᵉ primitive (Ed25519) ?

Le protocole sépare maintenant strictement quatre rôles
cryptographiques, chacun avec sa propre primitive et sa propre durée
de vie :

| Rôle                                   | Primitive   | Durée de vie                              |
|------------------------------------------|-------------|--------------------------------------------|
| Identité de session / signature           | **Ed25519** | Une session (régénérée à chaque `/connect`) |
| Établissement de secret de salon (invite)  | X25519      | Une invitation (ponctuel)                   |
| Dérivation de clé                          | HKDF-SHA256 | N/A (fonction pure)                         |
| Chiffrement des messages/fichiers          | AES-256-GCM / ChaCha20-Poly1305 | Une epoch (rotation) |

Ed25519 a été choisi plutôt que de détourner la clé X25519 existante
car **signer et chiffrer sont deux opérations cryptographiques
différentes** : réutiliser une même paire de clés pour les deux
affaiblit les garanties de sécurity de chacune (voir les mises en
garde classiques contre la réutilisation de clés Curve25519 entre
usages X25519/Ed25519). Ed25519 est le standard établi pour de la
signature sur courbe Edwards, avec la même famille de sécurité que
X25519 (128 bits), et une implémentation directement disponible dans
`cryptography` (`cryptography.hazmat.primitives.asymmetric.ed25519`).

### 9.2. Cycle de vie d'une session

```
Client                                          Server
  |                                                |
  | génère une paire Ed25519 ÉPHÉMÈRE              |
  | (jamais écrite sur disque)                      |
  |                                                |
  |── POST /session {public_key} ─────────────────>|
  |                                                | vérifie le format de la clé
  |                                                | tire session_id (32o aléatoires)
  |                                                | tire anonymous_number (6 chiffres,
  |                                                |   unique parmi les sessions actives)
  |                                                | stocke EN RAM SEULEMENT :
  |                                                |   session_id -> {public_key,
  |                                                |                  anonymous_number,
  |                                                |                  expires_at}
  |<── {session_id, anonymous_number, expires_in} ─|
  |                                                |
  | (affiche localement "Anonymous #NNNNNN")       |
  |                                                |
  |── POST /messages {enveloppe chiffrée,          |
  |     session_id, signature} ───────────────────>|
  |                                                | vérifie session_id connu + non expiré
  |                                                | vérifie signature avec la clé
  |                                                |   publique de CETTE session
  |                                                | stocke {enveloppe, anonymous_number}
  |                                                | diffuse aux autres clients connectés
  |<── enveloppe publique (id, ..., anonymous_number) |
```

Ce que `POST /session` NE fait PAS : il ne crée ni compte, ni mot de
passe, ni identifiant récupérable. Une nouvelle paire de clés = une
nouvelle session = un nouveau numéro, systématiquement.

### 9.3. Ce qui est signé, et comment le serveur vérifie

Le client signe la représentation canonique de l'enveloppe (les mêmes
octets, produits indépendamment et de façon identique par
`client/src/crypto.py::canonical_envelope_bytes` et
`server/src/protocol.py::canonical_envelope_bytes`) :

```
"{protocol_version}|{type}|{algorithm}|{key_id}|{nonce}|{ciphertext}"
```

La requête `POST /messages` transporte donc, en plus de l'enveloppe :

```json
{
  "...": "champs habituels de l'enveloppe",
  "session_id": "chaîne aléatoire opaque",
  "signature": "base64url(signature Ed25519)"
}
```

Le serveur :
1. rejette si `session_id` est inconnu ou expiré (`401`) ;
2. rejette si la signature ne vérifie pas avec la clé publique
   enregistrée pour CE `session_id` (`401`) — c'est ce qui empêche un
   client B de "voler" le numéro affiché d'un client A : même en
   connaissant (ou devinant) le `session_id` de A, B ne possède pas
   la clé privée correspondante et ne peut donc pas produire une
   signature valide ;
3. sinon, stocke le message avec le `anonymous_number` de la session
   (voir §9.4) et diffuse.

### 9.4. Pourquoi stocker `anonymous_number` en base (et rien d'autre)

`database.py` stocke `anonymous_number` (un entier 100000–999999) à
côté de chaque message. C'est une exception délibérée et documentée à
la règle générale "aucune colonne d'identité" :

- ce n'est **pas** un identifiant permanent : il est tiré aléatoirement
  à chaque nouvelle session et n'est associé, en RAM, qu'à la durée de
  vie de cette session (`session.ttl_seconds`, 6h par défaut) ;
- il **ne peut pas** être retrouvé à partir d'une clé publique, d'une
  IP, ou de quoi que ce soit d'autre : le lien
  `session_id -> anonymous_number` n'existe qu'en RAM et disparaît
  totalement au redémarrage du serveur ;
- le stocker ne crée aucune corrélation qui n'était pas déjà visible
  en direct : quelqu'un qui suit le salon en temps réel voit déjà
  quels messages partagent le même numéro pendant la session ; le
  stocker permet seulement à l'historique (pour un client qui
  rejoint plus tard) d'afficher la même cohérence, sans rien
  apprendre de plus sur qui se cache derrière ce numéro.

Ce que le serveur **ne stocke jamais**, même en RAM au-delà de la
durée de la session : la clé publique Ed25519 elle-même n'apparaît
JAMAIS dans SQLite, dans un fichier, ou dans les logs — uniquement
dans le dictionnaire en mémoire de `session.py`, purgé à l'expiration
ou au redémarrage.

### 9.5. Limites documentées

- **Un attaquant qui vole une session en cours** (ex. accès à la
  mémoire du processus client) peut continuer à signer sous ce
  numéro jusqu'à expiration. C'est un compromis assumé : le protocole
  protège contre l'usurpation par un tiers qui n'a jamais eu accès à
  la clé privée, pas contre le vol de cette clé elle-même.
- **Une collision de numéro** entre deux sessions concurrentes est
  possible sous très forte charge (le serveur évite activement les
  doublons parmi les sessions actives, mais retombe sur un tirage
  aléatoire simple après 50 tentatives infructueuses). Cela ne casse
  aucune propriété de sécurité : la vérification de signature reste
  liée à `session_id` (unique), le numéro n'est qu'un affichage.
- **Pas de fédération entre serveurs** : un numéro "Anonymous #583921"
  sur un serveur n'a aucune signification sur un autre serveur — les
  sessions, comme tout le reste, sont strictement locales à un
  serveur (voir docs/architecture.md).
- **Reconnexion = nouvelle session, mais l'ancienne reste valide
  jusqu'à expiration.** Le client ne "ferme" pas explicitement sa
  session précédente lors d'un nouveau `/connect` (pas d'endpoint de
  révocation dans cette version) : elle expire simplement au bout de
  `session.ttl_seconds`, ou disparaît immédiatement si le serveur
  redémarre entre-temps.

---

## 10. Administration sans identité

Un serveur a parfois besoin d'un rôle privilégié (recharger la
configuration, changer le mot de passe d'un salon...). Anonymous
fournit ce rôle **sans jamais créer de compte** :

- **Sans mot de passe admin configuré** (`[admin] password_hash` vide,
  valeur par défaut) : la PREMIÈRE session qui appelle
  `POST /admin/claim` depuis le démarrage du serveur devient admin.
  Toute tentative suivante échoue (`403`) jusqu'au prochain
  redémarrage.
- **Avec un mot de passe admin configuré** : n'importe quelle session
  qui le fournit devient admin — plusieurs sessions peuvent l'être
  simultanément si le mot de passe est partagé, exactement comme le
  mot de passe serveur global (`[auth]`).

Comme pour les messages (§9), chaque action admin (`/admin/reload`,
`/admin/rooms/password`) doit être signée avec la clé Ed25519 de la
session, sur une chaîne canonique propre à l'action :

```
"admin|claim"
"admin|reload"
"admin|room-password|<salon>|<mot_de_passe_ou_vide>"
```

**Le statut admin n'est stocké qu'en RAM** (`session.py`, jamais
SQLite) et **n'est jamais exposé** dans une réponse publique — ni
`/rooms`, ni `/status`, ni `/api/stats`, ni les enveloppes diffusées.
Un client qui devient admin le sait pour lui-même ; aucun autre
participant, y compris le serveur lui-même dans ses réponses
publiques, ne le révèle jamais. C'est une extension directe du
principe déjà appliqué aux sessions (§9) : un privilège technique
ponctuel, jamais une identité.

## 11. Fonctionnalités appliquées vs. indicatives

Anonymous distingue deux catégories de fonctionnalités optionnelles
(`[features]` dans `server.toml`), selon que le serveur PEUT ou NE
PEUT PAS techniquement les faire respecter :

| Fonctionnalité | Le serveur peut-il l'appliquer ? | Pourquoi |
|---|---|---|
| Réactions (`reactions_enabled`) | **Oui** | Le `type` d'enveloppe (`"reaction"`) est visible sans déchiffrement — le serveur peut accepter/refuser selon la configuration. |
| Indicateurs de frappe (`typing_indicators_enabled`) | **Oui** | Relayés en clair sur le canal WebSocket de contrôle (jamais stockés), le serveur peut simplement ne pas les relayer si désactivé. |
| Réponses (`replies_enabled`) | **Non — indicatif seulement** | `reply_to` vit à l'intérieur du contenu chiffré (`TextPayload`). Le serveur ne peut ni le voir, ni l'empêcher. |
| Échange de salon par X25519 (`room_exchange_enabled`) | **Non — indicatif seulement** | Mécanisme entièrement local aux clients (voir §3.2), le serveur n'y participe même pas. |

Cette distinction est **toujours indiquée honnêtement** dans
`/server-info` et cette documentation : Anonymous ne prétend jamais
qu'un réglage indicatif est une garantie technique.

## 12. Mode non-E2EE explicite (`[privacy] e2ee = false`)

Par défaut, `e2ee = true` : le serveur ne reçoit et ne peut jamais
recevoir de texte en clair, comme documenté dans tout ce fichier.

Un administrateur peut explicitement désactiver cette garantie
(`e2ee = false`) pour obtenir, en échange, une vraie modération
côté serveur (`[moderation] banned_words_enabled`). Dans ce mode
uniquement :

- le champ `algorithm` de l'enveloppe peut valoir `"none"` (au lieu de
  `AES-256-GCM`/`ChaCha20-Poly1305`) : `ciphertext` transporte alors
  réellement le texte en clair du message ;
- le serveur peut inspecter ce texte (recherche de mots bannis) avant
  de l'accepter, et le rejette avec un message générique
  (`"message rejected"`) sans jamais révéler quel mot a déclenché le
  rejet ;
- **si `e2ee = true` (défaut), `algorithm = "none"` est refusé** avec
  une erreur explicite : ce mode ne peut jamais s'activer par
  accident.

Le README et la page d'accueil du serveur (`GET /`) affichent un
avertissement clair quand ce mode est actif — voir docs/privacy.md
pour la formulation exacte et pourquoi ce choix doit rester explicite
et visible.
