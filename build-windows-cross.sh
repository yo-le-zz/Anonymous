#!/usr/bin/env bash
#
# Cross-compilation Windows DEPUIS Linux, via Wine — EXPÉRIMENTAL.
#
# ⚠ HONNÊTETÉ TECHNIQUE (lisez avant d'utiliser ce script) :
# Nuitka ne supporte pas la compilation croisée au sens strict : il
# compile pour la plateforme SUR LAQUELLE IL S'EXÉCUTE, pas pour une
# plateforme cible arbitraire (contrairement à des compilateurs comme
# Zig ou Rust). La seule façon de produire un .exe Windows sans
# posséder de machine Windows est de faire tourner un Python Windows
# ET Nuitka À L'INTÉRIEUR de Wine (émulation de l'API Windows sur
# Linux) — une approche réelle mais reconnue comme fragile : certaines
# versions de Python/Nuitka/dépendances (notamment `cryptography`, qui
# embarque du code C compilé) peuvent échouer à s'installer ou à
# tourner correctement sous Wine.
#
# Ce script est fourni en best-effort pour un test RAPIDE en local.
# La voie FIABLE et officielle pour les releases reste la compilation
# NATIVE sur un vrai runner Windows via GitHub Actions
# (.github/workflows/release.yml, job build-windows) — c'est elle qui
# produit les binaires effectivement publiés sur les Releases GitHub.
# N'utilisez ce script que pour un test local ponctuel ; en cas
# d'échec, ce n'est pas un bug du projet mais une limite connue de
# Wine pour ce genre de charge de travail.
#
# Prérequis : wine64, winetricks, et un installeur Python Windows
# embarqué (python-embed-amd64.zip, téléchargé automatiquement).

set -euo pipefail

VERSION="1.0.7"
DIST_DIR="dist/windows-cross"
WINEPREFIX="${WINEPREFIX:-$HOME/.wine-anonymous-build}"
PYTHON_EMBED_VERSION="3.12.7"
PYTHON_EMBED_URL="https://www.python.org/ftp/python/${PYTHON_EMBED_VERSION}/python-${PYTHON_EMBED_VERSION}-embed-amd64.zip"

echo "========================================"
echo " Cross-compilation Windows (EXPÉRIMENTAL)"
echo "========================================"
echo
echo "⚠ Voie non officielle — voir l'en-tête de ce script."
echo "  Pour une release fiable : poussez un tag et laissez"
echo "  .github/workflows/release.yml construire nativement sur"
echo "  un runner Windows."
echo

if ! command -v wine64 >/dev/null 2>&1; then
    echo "Erreur : wine64 n'est pas installé (sudo apt install wine64 winetricks)."
    exit 1
fi

mkdir -p "$DIST_DIR"
export WINEPREFIX
export WINEDEBUG=-all

if [ ! -f "$WINEPREFIX/drive_c/python-embed/python.exe" ]; then
    echo "[1/4] Téléchargement d'un Python Windows embarqué..."
    curl -fsSL -o /tmp/python-embed.zip "$PYTHON_EMBED_URL"
    mkdir -p "$WINEPREFIX/drive_c/python-embed"
    unzip -oq /tmp/python-embed.zip -d "$WINEPREFIX/drive_c/python-embed"

    # Un Python "embeddable" désactive `site` par défaut (donc pip et
    # les imports de paquets tiers) — il faut l'activer explicitement.
    PTH_FILE=$(find "$WINEPREFIX/drive_c/python-embed" -name "python*._pth" | head -1)
    if [ -n "$PTH_FILE" ]; then
        sed -i 's/^#import site/import site/' "$PTH_FILE"
    fi

    echo "[2/4] Installation de pip..."
    curl -fsSL -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
    wine64 "C:\\python-embed\\python.exe" Z:\\tmp\\get-pip.py --no-warn-script-location
fi

echo "[3/4] Installation des dépendances (peut échouer pour des paquets avec code C — voir avertissement ci-dessus)..."

# Le Python "embeddable" Windows n'a pas de roue (wheel) précompilée
# pour pip/setuptools/wheel eux-mêmes — sans cette étape, l'install de
# `nuitka` (qui n'a pas de wheel Windows pour cette config et doit
# donc être construit depuis son sdist) échoue avec :
#   pip._vendor.pyproject_hooks._impl.BackendUnavailable:
#   Cannot import 'setuptools.build_meta'
# car il n'y a pas de backend de build disponible pour le faire.
wine64 "C:\\python-embed\\python.exe" -m pip install --no-warn-script-location \
    --upgrade pip setuptools wheel

wine64 "C:\\python-embed\\python.exe" -m pip install --no-warn-script-location \
    "cryptography>=42.0.0" "requests>=2.31.0" "websockets>=13.0" \
    "windows-curses>=2.3.0" "nuitka>=2.8"

echo "[4/4] Compilation du client avec Nuitka sous Wine..."
wine64 "C:\\python-embed\\python.exe" -m nuitka \
    --onefile \
    --mingw64 \
    --follow-imports \
    --assume-yes-for-downloads \
    --include-module=websockets.asyncio.client \
    --include-package=cryptography \
    --include-package=requests \
    --output-dir="Z:\\$(pwd)/$DIST_DIR" \
    --output-filename=anonymous.exe \
    "Z:\\$(pwd)/client/src/main.py" || {
        echo
        echo "Échec de la compilation sous Wine — attendu pour certains"
        echo "environnements (voir l'avertissement en tête de ce script)."
        echo "Utilisez la release GitHub Actions officielle à la place."
        exit 1
    }

echo
echo "Binaire (best-effort) : $DIST_DIR/anonymous.exe"
echo "Testez-le sur une vraie machine Windows avant toute diffusion :"
echo "un binaire qui se construit sous Wine n'est pas garanti de"
echo "fonctionner correctement sur un vrai Windows."
