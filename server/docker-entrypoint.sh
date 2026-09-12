#!/bin/sh
# Entrypoint Docker du serveur Anonymous.
#
# Si /data/server.toml n'existe pas encore (premier lancement d'un
# volume neuf), on copie l'exemple par défaut avec les chemins de
# stockage adaptés à /data. Un `docker run` fonctionne ainsi sans
# configuration préalable, tout en respectant les mêmes réglages par
# défaut que le paquet .deb.

set -e

CONFIG_PATH="${ANONYMOUS_SERVER_CONFIG:-/data/server.toml}"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Aucune configuration trouvée, création de $CONFIG_PATH à partir de l'exemple par défaut..."
    sed \
        -e 's#^host = .*#host = "0.0.0.0"#' \
        -e 's#^database = .*#database = "/data/chat.db"#' \
        -e 's#^files = .*#files = "/data/files"#' \
        /app/server.toml.example > "$CONFIG_PATH"
fi

exec "$@"
