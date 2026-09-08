# HTTPS via reverse proxy — docs/https.md

Le serveur Anonymous écoute en HTTP simple (`host`/`port` dans
`server.toml`, `127.0.0.1:8000` par défaut) et **ne gère pas TLS
lui-même**. Pour l'exposer publiquement avec un certificat valide,
placez un reverse proxy devant lui. Les trois exemples ci-dessous
suffisent à exposer `https://chat.example.org` en redirigeant vers le
serveur local, HTTP **et** WebSocket (le WebSocket doit être
explicitement autorisé par le proxy, sinon `/ws` échoue silencieusement).

## Caddy (le plus simple — certificat automatique)

```caddyfile
chat.example.org {
    reverse_proxy 127.0.0.1:8000
}
```

Caddy détecte et proxifie automatiquement les WebSocket sur la même
directive `reverse_proxy` — rien de plus à faire.

## Nginx

```nginx
server {
    listen 443 ssl;
    server_name chat.example.org;

    ssl_certificate     /etc/letsencrypt/live/chat.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;

        # Nécessaire pour le WebSocket (/ws) :
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Uploads potentiellement volumineux :
        client_max_body_size 64m;
        proxy_read_timeout 3600s;
    }
}
```

## Traefik (labels Docker)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.anonymous.rule=Host(`chat.example.org`)"
  - "traefik.http.routers.anonymous.tls.certresolver=letsencrypt"
  - "traefik.http.services.anonymous.loadbalancer.server.port=8000"
```

Traefik gère nativement l'upgrade WebSocket sans configuration
additionnelle.

## Une fois HTTPS en place

Le client convertit automatiquement `https://` en `wss://` pour le
WebSocket (voir `client/src/protocol.py::build_ws_url`) : il suffit de
donner l'URL publique du domaine, jamais l'adresse interne
`127.0.0.1:8000` :

```
/connect https://chat.example.org
```

## HTTP simple (réseau local / test)

Anonymous ne force **jamais** HTTPS : sur un réseau local ou pour du
développement, `/connect http://192.168.1.20:8000` fonctionne
directement, sans reverse proxy. Le client affiche systématiquement un
avertissement dans ce cas :

```
⚠ Connexion en HTTP (non chiffré au niveau transport). Utilisez
https:// derrière un reverse proxy sur un réseau non fiable.
```

Le contenu des messages reste chiffré de bout en bout dans tous les
cas (voir `docs/crypto.md`) : cet avertissement concerne uniquement la
couche transport (quelqu'un observant le réseau verrait qu'une
connexion existe, sa taille approximative, et — sans TLS — qu'elle
utilise le protocole Anonymous, mais toujours pas le contenu des
messages).
