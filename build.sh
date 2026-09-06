#!/usr/bin/env bash
#
# Construit anonymous (client) et anonymous-server (serveur), chacun
# en exécutable autonome (Nuitka --onefile) puis en paquet .deb (meb).
#
# NOTE sur meb : cet outil (voir https://github.com/yo-le-zz/meb)
# semble lire un fichier `meb.toml` à la racine par défaut. Comme ce
# projet a DEUX cibles de packaging distinctes (client et serveur),
# ce script construit d'abord le client avec `meb.toml`, puis échange
# temporairement `meb-server.toml` à la place pour construire le
# serveur, avant de restaurer `meb.toml` d'origine. Si votre version
# de `meb` supporte un flag `--config`, remplacez ce mécanisme par
# `meb build --config meb-server.toml` (plus propre) — voir le
# commentaire en tête de meb-server.toml.

set -e

DIST_DIR="dist"
ICON="assets/anonymous.ico"

echo "========================================"
echo "        Building Anonymous v2"
echo "========================================"
echo

# ------------------------------------------------------------
# Vérifications
# ------------------------------------------------------------

if ! command -v uv >/dev/null 2>&1; then
    echo "Erreur : uv n'est pas installé."
    exit 1
fi

if ! command -v meb >/dev/null 2>&1; then
    echo "Erreur : meb n'est pas installé."
    exit 1
fi

for entry in "client/src/main.py" "server/src/main.py"; do
    if [ ! -f "$entry" ]; then
        echo "Erreur : point d'entrée introuvable : $entry"
        exit 1
    fi
done

if [ ! -f "$ICON" ]; then
    echo "Erreur : icône introuvable : $ICON"
    exit 1
fi

echo "[1/5] Nettoyage..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# ------------------------------------------------------------
# Compilation Nuitka — client
# ------------------------------------------------------------

echo
echo "[2/5] Compilation du client (Nuitka)..."
echo

uv run python -m nuitka \
    --onefile \
    --follow-imports \
    --output-dir="$DIST_DIR" \
    --output-filename="anonymous" \
    "client/src/main.py"

if [ ! -f "$DIST_DIR/anonymous" ]; then
    echo "Erreur : Nuitka n'a pas généré l'exécutable client attendu."
    exit 1
fi
chmod +x "$DIST_DIR/anonymous"
echo "Client généré : $DIST_DIR/anonymous"

# ------------------------------------------------------------
# Compilation Nuitka — serveur
# ------------------------------------------------------------

echo
echo "[3/5] Compilation du serveur (Nuitka)..."
echo

uv run python -m nuitka \
    --onefile \
    --follow-imports \
    --output-dir="$DIST_DIR" \
    --output-filename="anonymous-server" \
    "server/src/main.py"

if [ ! -f "$DIST_DIR/anonymous-server" ]; then
    echo "Erreur : Nuitka n'a pas généré l'exécutable serveur attendu."
    exit 1
fi
chmod +x "$DIST_DIR/anonymous-server"
echo "Serveur généré : $DIST_DIR/anonymous-server"

# ------------------------------------------------------------
# Paquet .deb — client
# ------------------------------------------------------------

echo
echo "[4/5] Construction du paquet .deb client..."
echo

meb build

# ------------------------------------------------------------
# Paquet .deb — serveur (échange temporaire de configuration)
# ------------------------------------------------------------

echo
echo "[5/5] Construction du paquet .deb serveur..."
echo

cp meb.toml meb.toml.client.bak
cp meb-server.toml meb.toml

cleanup_meb_swap() {
    if [ -f meb.toml.client.bak ]; then
        mv -f meb.toml.client.bak meb.toml
    fi
}
trap cleanup_meb_swap EXIT

meb build

cleanup_meb_swap
trap - EXIT

echo
echo "========================================"
echo "           BUILD TERMINÉ"
echo "========================================"
echo
echo "Exécutables :"
echo "  $DIST_DIR/anonymous"
echo "  $DIST_DIR/anonymous-server"
echo
echo "Paquets générés :"
find "$DIST_DIR" -maxdepth 1 -type f -name "*.deb" -print 2>/dev/null || true
echo
