#!/usr/bin/env bash
#
# Construit anonymous (client) et anonymous-server (serveur) en
# exécutables autonomes (Nuitka --onefile), puis assemble des paquets
# .deb Linux directement avec dpkg-deb — plus aucune dépendance à
# l'outil tiers `meb`.
#
# Ce script cible Linux (amd64). Pour Windows, voir
# .github/workflows/release.yml qui appelle Nuitka directement sur un
# runner windows-latest (Nuitka doit tourner sur l'OS cible).
#
# Usage :
#   ./build.sh            build complet (binaires + .deb)
#   ./build.sh binaries    binaires seulement, pas de .deb

set -euo pipefail

VERSION="1.0.3"
ARCH="amd64"
DIST_DIR="dist"
PKG_DIR="$DIST_DIR/pkg"

MODE="${1:-all}"

echo "========================================"
echo "   Building Anonymous v$VERSION (Linux)"
echo "========================================"
echo

# ------------------------------------------------------------
# Vérifications
# ------------------------------------------------------------

if ! command -v uv >/dev/null 2>&1; then
    echo "Erreur : uv n'est pas installé (https://github.com/astral-sh/uv)."
    exit 1
fi

for entry in "client/src/main.py" "server/src/main.py"; do
    if [ ! -f "$entry" ]; then
        echo "Erreur : point d'entrée introuvable : $entry"
        exit 1
    fi
done

echo "[1/4] Nettoyage..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# ------------------------------------------------------------
# Compilation Nuitka — client et serveur
# ------------------------------------------------------------

echo
echo "[2/4] Compilation du client (Nuitka --onefile)..."
uv run python -m nuitka \
    --onefile \
    --follow-imports \
    --include-module=websockets.asyncio.client \
    --include-package=cryptography \
    --include-package=requests \
    --output-dir="$DIST_DIR" \
    --output-filename="anonymous" \
    "client/src/main.py"

[ -f "$DIST_DIR/anonymous" ] || { echo "Erreur : binaire client non généré."; exit 1; }
chmod +x "$DIST_DIR/anonymous"
echo "Client généré : $DIST_DIR/anonymous"

echo
echo "[3/4] Compilation du serveur (Nuitka --onefile)..."
uv run python -m nuitka \
    --onefile \
    --follow-imports \
    --include-package=uvicorn \
    --include-package=starlette \
    --include-package=fastapi \
    --include-package=pydantic \
    --include-package=websockets \
    --include-package=cryptography \
    --include-package=argon2 \
    --output-dir="$DIST_DIR" \
    --output-filename="anonymous-server" \
    "server/src/main.py"

[ -f "$DIST_DIR/anonymous-server" ] || { echo "Erreur : binaire serveur non généré."; exit 1; }
chmod +x "$DIST_DIR/anonymous-server"
echo "Serveur généré : $DIST_DIR/anonymous-server"

if [ "$MODE" = "binaries" ]; then
    echo
    echo "Binaires seuls demandés (./build.sh binaries) — pas de .deb."
    exit 0
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo
    echo "dpkg-deb introuvable : binaires générés, mais paquets .deb non construits."
    echo "Installez dpkg-dev (apt install dpkg-dev) pour construire les .deb."
    exit 0
fi

echo
echo "[4/4] Construction des paquets .deb..."
rm -rf "$PKG_DIR"

# ------------------------------------------------------------
# Paquet client : anonymous_$VERSION_$ARCH.deb
# ------------------------------------------------------------

CLIENT_ROOT="$PKG_DIR/client"
mkdir -p "$CLIENT_ROOT/DEBIAN" \
         "$CLIENT_ROOT/usr/bin" \
         "$CLIENT_ROOT/usr/share/applications" \
         "$CLIENT_ROOT/usr/share/pixmaps" \
         "$CLIENT_ROOT/usr/share/doc/anonymous"

cp "$DIST_DIR/anonymous" "$CLIENT_ROOT/usr/bin/anonymous"
chmod 0755 "$CLIENT_ROOT/usr/bin/anonymous"
cp README.md "$CLIENT_ROOT/usr/share/doc/anonymous/README.md"
[ -f assets/anonymous.png ] && cp assets/anonymous.png "$CLIENT_ROOT/usr/share/pixmaps/anonymous.png"

cat > "$CLIENT_ROOT/usr/share/applications/anonymous.desktop" << EOF
[Desktop Entry]
Type=Application
Name=Anonymous
Comment=Chat chiffré de bout en bout, sans compte ni serveur central
Exec=/usr/bin/anonymous
Icon=anonymous
Terminal=true
Categories=Network;Chat;
EOF

INSTALLED_SIZE_CLIENT=$(du -sk "$CLIENT_ROOT/usr" | cut -f1)

cat > "$CLIENT_ROOT/DEBIAN/control" << EOF
Package: anonymous
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $INSTALLED_SIZE_CLIENT
Maintainer: yolezz
Description: Client de chat chiffré de bout en bout, sans compte ni serveur central
 Anonymous est un client terminal pour un chat de groupe chiffré de
 bout en bout (X25519 + HKDF-SHA256 + AES-256-GCM/ChaCha20-Poly1305).
 Aucun compte, aucune identité persistante : voir docs/crypto.md et
 docs/privacy.md dans le dépôt source pour le modèle de menace complet.
EOF

find "$CLIENT_ROOT" -type d -exec chmod 0755 {} \;
find "$CLIENT_ROOT" -type f -not -path "*/DEBIAN/*" -exec chmod 0644 {} \;
chmod 0755 "$CLIENT_ROOT/usr/bin/anonymous"

dpkg-deb --root-owner-group --build "$CLIENT_ROOT" "$DIST_DIR/anonymous_${VERSION}_${ARCH}.deb"

# ------------------------------------------------------------
# Paquet serveur : anonymous-server_$VERSION_$ARCH.deb
# ------------------------------------------------------------

SERVER_ROOT="$PKG_DIR/server"
mkdir -p "$SERVER_ROOT/DEBIAN" \
         "$SERVER_ROOT/usr/bin" \
         "$SERVER_ROOT/etc/anonymous" \
         "$SERVER_ROOT/lib/systemd/system" \
         "$SERVER_ROOT/usr/share/doc/anonymous-server"

cp "$DIST_DIR/anonymous-server" "$SERVER_ROOT/usr/bin/anonymous-server"
chmod 0755 "$SERVER_ROOT/usr/bin/anonymous-server"
cp etc/anonymous/server.toml "$SERVER_ROOT/etc/anonymous/server.toml"
cp server/systemd/anonymous-server.service "$SERVER_ROOT/lib/systemd/system/anonymous-server.service"
cp README.md "$SERVER_ROOT/usr/share/doc/anonymous-server/README.md"

cp server/debian/postinst "$SERVER_ROOT/DEBIAN/postinst"
cp server/debian/prerm "$SERVER_ROOT/DEBIAN/prerm"
cp server/debian/postrm "$SERVER_ROOT/DEBIAN/postrm"
chmod 0755 "$SERVER_ROOT/DEBIAN/postinst" "$SERVER_ROOT/DEBIAN/prerm" "$SERVER_ROOT/DEBIAN/postrm"

echo "/etc/anonymous/server.toml" > "$SERVER_ROOT/DEBIAN/conffiles"

INSTALLED_SIZE_SERVER=$(du -sk "$SERVER_ROOT/usr" "$SERVER_ROOT/etc" "$SERVER_ROOT/lib" | awk '{sum+=$1} END {print sum}')

cat > "$SERVER_ROOT/DEBIAN/control" << EOF
Package: anonymous-server
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $INSTALLED_SIZE_SERVER
Maintainer: yolezz
Description: Serveur relais chiffré Anonymous — sans identité applicative
 Serveur FastAPI/WebSocket/SQLite pour le chat chiffré de bout en bout
 Anonymous. Ne possède jamais les clés de déchiffrement des messages,
 aucune identité utilisateur persistante. Installe un service systemd
 tournant sous un utilisateur système dédié (jamais root).
 .
 Voir /etc/anonymous/server.toml pour la configuration et
 docs/server.md dans le dépôt source pour l'exploitation complète.
EOF

find "$SERVER_ROOT" -type d -exec chmod 0755 {} \;
find "$SERVER_ROOT" -type f -not -path "*/DEBIAN/*" -exec chmod 0644 {} \;
chmod 0755 "$SERVER_ROOT/usr/bin/anonymous-server"
chmod 0755 "$SERVER_ROOT/DEBIAN/postinst" "$SERVER_ROOT/DEBIAN/prerm" "$SERVER_ROOT/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "$SERVER_ROOT" "$DIST_DIR/anonymous-server_${VERSION}_${ARCH}.deb"

rm -rf "$PKG_DIR"

echo
echo "========================================"
echo "           BUILD TERMINÉ"
echo "========================================"
echo
echo "Exécutables :"
echo "  $DIST_DIR/anonymous"
echo "  $DIST_DIR/anonymous-server"
echo
echo "Paquets Debian :"
find "$DIST_DIR" -maxdepth 1 -type f -name "*.deb" -print
echo
