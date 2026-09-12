"""
Assistant de configuration interactif : `anonymous-server config`.

Découplé en deux parties pour rester testable :
- la logique (schéma des champs, validation, écriture TOML) est du
  Python pur, sans dépendance à curses ;
- `run_wizard()` fait le rendu curses et appelle la logique ci-dessus.

Chaque champ affiche sa valeur actuelle ET une explication claire de
ce qu'il fait, comme demandé. La navigation est un menu (pas un
assistant linéaire strict) : on peut toujours revenir en arrière en
quittant l'édition d'un champ sans le valider.
"""

from __future__ import annotations

import copy
import dataclasses
from typing import Any


@dataclasses.dataclass
class ConfigField:
    section: str
    key: str
    label: str
    description: str
    field_type: str  # "bool" | "int" | "str"


FIELDS: list[ConfigField] = [
    ConfigField("server", "host", "Adresse d'écoute",
                "Interface réseau sur laquelle le serveur écoute. "
                "127.0.0.1 = accessible uniquement en local (recommandé "
                "derrière un reverse proxy, voir docs/https.md).", "str"),
    ConfigField("server", "port", "Port d'écoute",
                "Port TCP local du serveur.", "int"),
    ConfigField("auth", "enabled", "Mot de passe serveur requis",
                "Si activé, les clients doivent fournir un mot de passe "
                "pour utiliser ce serveur. Générez le hash avec la "
                "commande : anonymous-server hash-password.", "bool"),
    ConfigField("rooms", "enabled", "Salons activés",
                "Active le système de salons (canaux nommés). Si "
                "désactivé, tout le monde partage un espace unique.", "bool"),
    ConfigField("rooms", "allow_public_rooms", "Création libre de salons",
                "Permet aux clients de créer eux-mêmes de nouveaux "
                "salons publics à la volée.", "bool"),
    ConfigField("rooms", "max_rooms", "Nombre maximal de salons",
                "Limite anti-abus sur le nombre total de salons créés.", "int"),
    ConfigField("features", "reactions_enabled", "Réactions activées",
                "Autorise les réactions emoji aux messages. Réellement "
                "appliqué côté serveur (le type d'enveloppe est visible "
                "sans déchiffrement).", "bool"),
    ConfigField("features", "typing_indicators_enabled", "Indicateurs de frappe",
                "Relaie en direct \"X est en train d'écrire\". Jamais "
                "stocké en base.", "bool"),
    ConfigField("features", "replies_enabled", "Réponses (indicatif)",
                "Signale aux clients si les réponses sont encouragées. "
                "PUREMENT INDICATIF : le contenu est chiffré, le serveur "
                "ne peut techniquement pas l'imposer.", "bool"),
    ConfigField("ratelimit", "messages_per_minute", "Messages / minute / IP",
                "Limite anti-spam de base sur l'envoi de messages.", "int"),
    ConfigField("ratelimit", "progressive_cooldown_enabled", "Cooldown anti-spam progressif",
                "Double la pénalité à chaque récidive (1s, 2s, 4s...) au "
                "lieu d'un simple rejet fixe.", "bool"),
    ConfigField("privacy", "e2ee", "Chiffrement de bout en bout obligatoire",
                "ATTENTION : désactiver ceci permet une vraie modération "
                "côté serveur mais SUPPRIME la confidentialité de bout en "
                "bout pour tous les messages. Voir docs/privacy.md. "
                "Valeur par défaut : activé.", "bool"),
    ConfigField("moderation", "banned_words_enabled", "Liste de mots bannis",
                "N'est réellement appliqué par le serveur QUE si le "
                "chiffrement de bout en bout ci-dessus est désactivé ; "
                "sinon c'est seulement publié via /policy pour un "
                "filtrage indicatif côté client.", "bool"),
    ConfigField("moderation", "banned_words_file", "Fichier de mots bannis",
                "Chemin vers un fichier texte (un mot par ligne).", "str"),
    ConfigField("retention", "enabled", "Rétention automatique",
                "Active la suppression automatique des anciens messages.", "bool"),
    ConfigField("retention", "max_age_seconds", "Âge maximal (secondes)",
                "0 = illimité. Les messages plus vieux que cette durée "
                "sont supprimés automatiquement.", "int"),
    ConfigField("files", "enabled", "Fichiers activés",
                "Autorise l'envoi de fichiers chiffrés par les clients.", "bool"),
    ConfigField("files", "max_file_size", "Taille max par fichier (octets)",
                "Limite anti-abus sur la taille d'un fichier envoyé.", "int"),
    ConfigField("web", "enabled", "Page web publique",
                "Active la page de statut publique (/) et /status.", "bool"),
    ConfigField("web", "server_name", "Nom affiché du serveur",
                "Nom affiché en haut de la page web publique.", "str"),
    ConfigField("admin", "password_hash", "Mot de passe admin (hash Argon2id)",
                "Laisser vide : la PREMIÈRE session qui le demande devient "
                "admin. Générez un hash avec : "
                "anonymous-server generate-admin-password-hash.", "str"),
    ConfigField("temporary", "enabled", "Serveur temporaire",
                "Si activé, le serveur s'éteint et purge toutes ses "
                "données après la durée de vie ci-dessous.", "bool"),
    ConfigField("temporary", "lifetime_seconds", "Durée de vie (secondes)",
                "Durée avant extinction automatique, si serveur "
                "temporaire activé ci-dessus.", "int"),
]


def load_current_values(config_dict: dict) -> dict[tuple[str, str], Any]:
    values: dict[tuple[str, str], Any] = {}
    for field in FIELDS:
        section = config_dict.get(field.section, {})
        values[(field.section, field.key)] = section.get(field.key)
    return values


def format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "oui" if value else "non"
    if value is None or value == "":
        return "(vide)"
    return str(value)


def apply_edit(values: dict, field: ConfigField, raw_input: str) -> tuple[bool, str]:
    """Convertit `raw_input` selon le type du champ et met à jour
    `values` en place. Retourne (succès, message_erreur_si_échec) — en
    cas d'échec, `values` n'est PAS modifié, pour permettre de
    corriger la saisie sans perdre l'ancienne valeur valide."""

    key = (field.section, field.key)
    raw_input = raw_input.strip()

    if field.field_type == "bool":
        lowered = raw_input.lower()
        if lowered in ("o", "oui", "y", "yes", "true", "1"):
            values[key] = True
            return True, ""
        if lowered in ("n", "non", "no", "false", "0"):
            values[key] = False
            return True, ""
        return False, "Répondez par oui/non (o/n)."

    if field.field_type == "int":
        try:
            values[key] = int(raw_input)
            return True, ""
        except ValueError:
            return False, "Entrez un nombre entier."

    values[key] = raw_input
    return True, ""


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _dict_to_toml(data: dict) -> str:
    lines = [
        "# Généré par l'assistant de configuration (anonymous-server config).",
        "# Voir docs/server.md pour la description complète de chaque option.",
        "",
    ]

    for section, section_values in data.items():
        if not isinstance(section_values, dict):
            continue
        lines.append(f"[{section}]")
        for key, value in section_values.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")

    return "\n".join(lines)


def build_toml(values: dict[tuple[str, str], Any], base_config: dict) -> str:
    """Reconstruit un TOML complet à partir des valeurs éditées, en
    conservant TOUTES les autres clés de `base_config` (celles que
    l'assistant n'expose pas dans `FIELDS`) inchangées — l'assistant
    n'écrase jamais un réglage qu'il ne montre pas."""

    merged = copy.deepcopy(base_config)

    for (section, key), value in values.items():
        merged.setdefault(section, {})[key] = value

    return _dict_to_toml(merged)


# ============================================================
# RENDU CURSES
# ============================================================

def run_wizard(base_config: dict, output_path: str) -> None:
    import curses

    def _ui(stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)

        values = load_current_values(base_config)
        selected = 0
        message = ""

        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()

            title = " Anonymous — assistant de configuration "
            stdscr.addstr(0, max(0, (width - len(title)) // 2), title,
                          curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(1, 2, "↑/↓ naviguer   Entrée modifier   s enregistrer   q quitter sans enregistrer",
                          curses.color_pair(2))

            visible_height = max(1, height - 6)
            start = max(0, selected - visible_height + 1)

            for row, field in enumerate(FIELDS[start:start + visible_height]):
                index = start + row
                current = values[(field.section, field.key)]
                line = f"{field.label} : {format_value(current)}"
                attr = curses.A_REVERSE if index == selected else curses.A_NORMAL
                try:
                    stdscr.addstr(3 + row, 2, line[: max(0, width - 4)], attr)
                except curses.error:
                    pass

            description = FIELDS[selected].description
            desc_y = height - 3
            try:
                stdscr.addstr(desc_y, 2, description[: max(0, width - 4)], curses.color_pair(3))
            except curses.error:
                pass

            if message:
                try:
                    stdscr.addstr(height - 1, 2, message[: max(0, width - 4)], curses.color_pair(2))
                except curses.error:
                    pass

            stdscr.refresh()
            key_pressed = stdscr.getch()

            if key_pressed in (curses.KEY_UP,) and selected > 0:
                selected -= 1
                message = ""
            elif key_pressed in (curses.KEY_DOWN,) and selected < len(FIELDS) - 1:
                selected += 1
                message = ""
            elif key_pressed in (curses.KEY_ENTER, 10, 13):
                field = FIELDS[selected]
                curses.curs_set(1)
                curses.echo()
                prompt = f"Nouvelle valeur pour « {field.label} » (actuel: {format_value(values[(field.section, field.key)])}) : "
                stdscr.addstr(height - 2, 2, prompt[: max(0, width - 4)])
                stdscr.refresh()
                raw = stdscr.getstr(height - 2, min(width - 4, 2 + len(prompt)), 200).decode("utf-8", errors="ignore")
                curses.noecho()
                curses.curs_set(0)

                if raw.strip():
                    ok, error = apply_edit(values, field, raw)
                    message = "Valeur mise à jour." if ok else f"Erreur : {error}"
                else:
                    message = "Inchangé."
            elif key_pressed in (ord("s"), ord("S")):
                toml_text = build_toml(values, base_config)
                with open(output_path, "w", encoding="utf-8") as handle:
                    handle.write(toml_text)
                message = f"Enregistré dans {output_path}."
                stdscr.addstr(height - 1, 2, message[: max(0, width - 4)], curses.color_pair(3))
                stdscr.refresh()
                stdscr.getch()
                return
            elif key_pressed in (ord("q"), ord("Q"), 27):
                return

    curses.wrapper(_ui)
