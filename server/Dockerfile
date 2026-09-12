# Image Docker du serveur Anonymous — alternative au paquet .deb pour
# héberger sur n'importe quel système (voir docs/server.md).
#
# Build (depuis la racine du dépôt) :
#   docker build -f server/Dockerfile -t anonymous-server .
# Run :
#   docker run -p 8000:8000 -v anonymous-data:/data anonymous-server

FROM python:3.12-slim

# Utilisateur système dédié, jamais root — même principe que le
# paquet .deb (voir server/debian/postinst).
RUN groupadd --system anonymous && \
    useradd --system --gid anonymous --home-dir /data --shell /usr/sbin/nologin anonymous

WORKDIR /app

COPY server/src /app/server/src
COPY etc/anonymous/server.toml /app/server.toml.example
COPY server/docker-entrypoint.sh /app/docker-entrypoint.sh

RUN pip install --no-cache-dir \
        "cryptography>=42.0.0" \
        "fastapi>=0.110.0" \
        "uvicorn>=0.29.0" \
        "pydantic>=2.6.0" \
        "argon2-cffi>=23.1.0" \
        "websockets>=13.0" && \
    chmod +x /app/docker-entrypoint.sh && \
    mkdir -p /data/files && \
    chown -R anonymous:anonymous /data /app

VOLUME ["/data"]
EXPOSE 8000

ENV ANONYMOUS_SERVER_CONFIG=/data/server.toml
ENV PYTHONUNBUFFERED=1

USER anonymous
WORKDIR /app/server/src

# Si /data/server.toml n'existe pas encore, l'entrypoint copie
# l'exemple par défaut (chemins adaptés à /data) avant de démarrer,
# pour qu'un simple `docker run` fonctionne sans configuration
# préalable — voir server/docker-entrypoint.sh.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python3", "main.py"]
