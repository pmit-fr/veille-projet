#!/usr/bin/env python3
"""
Veille PROJET (déménagement) — publication quotidienne (jours ouvrés) sur GitHub Pages
(projet.pmit.fr).

Même mécanique que le dépôt veille-auto-publish (page CVE quotidienne),
dans un dépôt séparé pour ne jamais risquer de casser la page CVE :

  1. Une tâche planifiée Claude écrit chaque jour ouvré un fichier JSON
     ("veille-projet-items.json") sur le site SharePoint "Veillepublication".
  2. Ce script le lit (app Azure AD en lecture seule, Sites.Selected),
     le valide, génère les pages HTML, archive l'édition dans data/.
  3. Le workflow GitHub Actions publie le dossier public/ sur GitHub Pages.

AUCUN appel à l'API Anthropic ici. Coût récurrent nul (dépôt public).

La page est organisée en deux zones :
  - ZONE 1, en tête : Réglementation (RGPD, RSE / numérique responsable,
    télécoms). Catégorie choisie par la tâche, contrôlée contre une liste
    fermée.
  - ZONE 2, ensuite : Suivi du matériel du projet (Fortinet, Unifi,
    Synology, Veeam, Maxhub). Catégorie décidée ICI, de façon déterministe,
    à partir du nom du produit — la catégorie du JSON n'est qu'indicative.
  - Tout le reste part dans "Autres actualités", replié en bas.

PAGE PUBLIQUE : ne jamais y mettre d'information confidentielle sur le
client (nom, adresse, plans, prestataires). La tâche planifiée a la même
consigne.

POSTURE SÉCURITÉ (identique à la page CVE) : le JSON provient d'une
recherche web faite par un modèle, donc potentiellement influencé par du
contenu piégé. Il n'est jamais inséré tel quel :
  - échappement systématique (html.escape)
  - URLs http/https uniquement
  - catégories et niveaux contrôlés contre des listes fermées
  - template HTML fixe dans ce script
  - archives de data/ re-validées à la relecture

Variables d'environnement :
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET  (obligatoires)
  SHAREPOINT_DRIVE_ID                                    (obligatoire)
  SHAREPOINT_FILE_NAME  (défaut : veille-projet-items.json)
  OUTPUT_DIR            (défaut : public)
  ARCHIVE_DIR           (défaut : data)
"""

import calendar
import html as html_lib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote, urlparse

# ─────────────────────────────────────────────────────────────────────────
# ZONE 1 — Réglementation (affichée en premier, mise en avant)
# ─────────────────────────────────────────────────────────────────────────
REGULATION_CATEGORIES = {
    "rgpd": ("🔒", "RGPD & protection des données", "CNIL, CEPD, décisions et recommandations"),
    "rse": ("🌱", "RSE & numérique responsable", "RGESN, recyclage, sobriété, inclusion"),
    "telecom": ("📶", "Télécoms & accès internet", "Arcep, fibre, opérateurs"),
}

# ─────────────────────────────────────────────────────────────────────────
# ZONE 2 — Matériel du projet (catégorie décidée par le nom du produit)
# ─────────────────────────────────────────────────────────────────────────
HARDWARE_CATEGORIES = {
    "routeur": ("🧱", "Routeur & pare-feu", "Fortinet"),
    "wifi": ("📡", "Bornes Wi-Fi & réseau", "Unifi"),
    "nas": ("🗄️", "NAS", "Synology"),
    "sauvegarde": ("💾", "Sauvegarde", "Veeam"),
    "visio": ("🎥", "Visioconférence", "Maxhub"),
}

OTHER_CATEGORY = ("📰", "Autres actualités (hors périmètre)")

HARDWARE_KEYWORDS: list[tuple[str, str]] = [
    ("fortigate", "routeur"), ("fortios", "routeur"), ("fortiswitch", "routeur"),
    ("fortiap", "routeur"), ("fortinet", "routeur"),
    ("unifi", "wifi"), ("ubiquiti", "wifi"),
    ("synology", "nas"), ("diskstation", "nas"), ("dsm", "nas"),
    ("veeam", "sauvegarde"),
    ("maxhub", "visio"),
]

ALLOWED_CATEGORIES = set(REGULATION_CATEGORIES) | set(HARDWARE_CATEGORIES) | {"hors_perimetre"}

# Niveaux pensés pour un chef de projet (mêmes clés que la page CVE pour
# garder un format de JSON commun).
ALLOWED_CRITICALITY = {
    "critique": ("🔴", "ACTION REQUISE"),
    "important": ("🟠", "À SURVEILLER"),
    "info": ("🟢", "POUR INFO"),
}
CRITICALITY_ORDER = ["critique", "important", "info"]
CRIT_CSS_CLASS = {"critique": "crit", "important": "imp", "info": "info"}

MAX_FIELD_LEN = {"product": 80, "impact": 300, "technical_detail": 600, "source": 120}
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
FR_MONTHS = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
]


def classify(item: dict) -> str:
    """Zone 1 si la tâche a choisi une catégorie réglementaire connue ;
    sinon zone 2 si le produit correspond au matériel du projet ; sinon
    hors périmètre."""
    if item["category"] in REGULATION_CATEGORIES:
        return item["category"]
    p = item["product"].lower()
    for keyword, category in HARDWARE_KEYWORDS:
        if keyword in p:
            return category
    return "hors_perimetre"


# ─────────────────────────────────────────────────────────────────────────
# Lecture SharePoint (app-only, lecture seule, Sites.Selected)
# ─────────────────────────────────────────────────────────────────────────
def _get_app_only_token() -> str:
    import msal

    app = msal.ConfidentialClientApplication(
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_credential=os.environ["AZURE_CLIENT_SECRET"],
        authority=f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}",
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            "Impossible d'obtenir un jeton Azure AD : "
            f"{result.get('error')}: {result.get('error_description')}"
        )
    return result["access_token"]


def fetch_items_from_sharepoint() -> dict:
    token = _get_app_only_token()
    drive_id = os.environ["SHAREPOINT_DRIVE_ID"]
    file_name = os.environ.get("SHAREPOINT_FILE_NAME", "veille-projet-items.json")
    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{quote(file_name)}:/content"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}", "User-Agent": "veille-projet-bot/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace").strip()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Erreur HTTP {exc.code} sur {file_name!r} : {body[:300]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Impossible de télécharger le fichier SharePoint : {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON invalide : {exc} — début : {raw[:300]!r}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise RuntimeError(f"Structure JSON inattendue : {raw[:300]!r}")
    return data


# ─────────────────────────────────────────────────────────────────────────
# Validation / nettoyage
# ─────────────────────────────────────────────────────────────────────────
def _truncate(text: str, max_len: int) -> str:
    text = text.strip()
    return text[: max_len - 1].rstrip() + "…" if len(text) > max_len else text


def _valid_url(url) -> str | None:
    if not isinstance(url, str):
        return None
    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return url


def sanitize_items(raw_items: list) -> list[dict]:
    clean = []
    for idx, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            print(f"Item #{idx} ignoré (pas un objet)", file=sys.stderr)
            continue
        category = raw.get("category")
        if category not in ALLOWED_CATEGORIES:
            print(f"Item #{idx} ignoré (catégorie inconnue : {category!r})", file=sys.stderr)
            continue
        criticality = raw.get("criticality")
        if criticality not in ALLOWED_CRITICALITY:
            print(f"Item #{idx} ignoré (niveau inconnu : {criticality!r})", file=sys.stderr)
            continue
        url = _valid_url(raw.get("url", ""))
        if url is None:
            print(f"Item #{idx} ignoré (URL absente ou non http/https)", file=sys.stderr)
            continue
        impact = raw.get("impact")
        if not isinstance(impact, str) or not impact.strip():
            print(f"Item #{idx} ignoré (impact manquant)", file=sys.stderr)
            continue
        clean.append({
            "category": category,
            "product": _truncate(str(raw.get("product", "Autre")), MAX_FIELD_LEN["product"]),
            "criticality": criticality,
            "impact": _truncate(impact, MAX_FIELD_LEN["impact"]),
            "technical_detail": _truncate(str(raw.get("technical_detail", "")), MAX_FIELD_LEN["technical_detail"]),
            "source": _truncate(str(raw.get("source", "")), MAX_FIELD_LEN["source"]),
            "date": _truncate(str(raw.get("date", "")), 20),
            "url": url,
        })
    return clean


# ─────────────────────────────────────────────────────────────────────────
# Dates (heure de Paris, sans dépendance externe) et archives quotidiennes
# ─────────────────────────────────────────────────────────────────────────
def _last_sunday(year: int, month: int) -> date:
    d = date(year, month, calendar.monthrange(year, month)[1])
    return d - timedelta(days=(d.weekday() - 6) % 7)


def paris_today(now_utc: datetime | None = None) -> date:
    now_utc = now_utc or datetime.now(timezone.utc)
    y = now_utc.year
    dst_start = datetime(y, 3, _last_sunday(y, 3).day, 1, tzinfo=timezone.utc)
    dst_end = datetime(y, 10, _last_sunday(y, 10).day, 1, tzinfo=timezone.utc)
    return (now_utc + timedelta(hours=2 if dst_start <= now_utc < dst_end else 1)).date()


def week_monday(d: date) -> date:
    return d - timedelta(days=d.weekday())


FR_WEEKDAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
FR_WEEKDAYS_SHORT = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"]


def day_label(d: date) -> str:
    return f"{FR_WEEKDAYS[d.weekday()].capitalize()} {d.day} {FR_MONTHS[d.month - 1]} {d.year}"


def _archive_path(archive_dir: str, monday: date) -> str:
    return os.path.join(archive_dir, f"{monday.isoformat()}.json")


def save_archive(archive_dir: str, monday: date, page_date: str, items: list[dict]) -> None:
    os.makedirs(archive_dir, exist_ok=True)
    payload = {"schema": 1, "date_key": monday.isoformat(), "page_date": page_date, "items": items}
    with open(_archive_path(archive_dir, monday), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")


def load_archive(archive_dir: str, monday: date) -> dict | None:
    path = _archive_path(archive_dir, monday)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Archive {path} illisible, ignorée : {exc}", file=sys.stderr)
        return None
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    return {
        "page_date": _truncate(str(payload.get("page_date", "")), 40),
        "items": sanitize_items(items if isinstance(items, list) else []),
    }


def all_archive_weeks(archive_dir: str) -> list[date]:
    if not os.path.isdir(archive_dir):
        return []
    weeks = []
    for name in os.listdir(archive_dir):
        if name.endswith(".json"):
            try:
                weeks.append(date.fromisoformat(name[:-5]))
            except ValueError:
                continue
    return sorted(weeks, reverse=True)


# ─────────────────────────────────────────────────────────────────────────
# Rendu HTML
# ─────────────────────────────────────────────────────────────────────────
def esc(value: str) -> str:
    return html_lib.escape(value, quote=True)


def build_sidebar(weeks: list[date], current: date, active: date, location: str) -> str:
    if not weeks:
        return ""
    entries = []
    for w in weeks:
        if location == "root":
            href = f"archive/{w.isoformat()}.html"
        else:
            href = "../index.html" if w == current else f"{w.isoformat()}.html"
        label = f'<span class="day-name">{FR_WEEKDAYS_SHORT[w.weekday()]}</span><span class="day-num">{w.day:02d}/{w.month:02d}</span>'
        if w == active:
            entries.append(f'<span class="day-item active">{label}</span>')
        else:
            entries.append(f'<a class="day-item" href="{href}">{label}</a>')
    return f'''<aside class="sidebar">
  <div class="sidebar-scroll">
    <div class="sidebar-label">Éditions</div>
    <nav class="day-list">
      {"".join(entries)}
    </nav>
  </div>
</aside>'''


def _render_cards(items: list[dict]) -> str:
    out = []
    for item in sorted(items, key=lambda i: CRITICALITY_ORDER.index(i["criticality"])):
        css = CRIT_CSS_CLASS[item["criticality"]]
        icon, label = ALLOWED_CRITICALITY[item["criticality"]]
        detail = (
            f'<div class="level2-label">Détail</div><p class="tech">{esc(item["technical_detail"])}</p>'
            if item["technical_detail"] else ""
        )
        out.append(f'''<a class="card {css}" href="{esc(item["url"])}" target="_blank" rel="noopener noreferrer">
    <div class="card-top"><span class="badge {css}">{icon} {label}</span></div>
    <div class="level1">{esc(item["impact"])}</div>
    <div class="level2">
      <div class="meta">{esc(item["source"])} · {esc(item["date"])}</div>
      {detail}
    </div>
  </a>''')
    return "".join(out)


def _render_groups(items: list[dict]) -> str:
    groups: dict[str, list[dict]] = {}
    for item in items:
        groups.setdefault(item["product"], []).append(item)
    return "".join(
        f'''<div class="subgroup">
    <div class="subgroup-title">→ {esc(name)}</div>
    <div class="cards">{_render_cards(group)}</div>
  </div>'''
        for name, group in groups.items()
    )


def _render_section(icon: str, label: str, hint: str, items: list[dict]) -> str:
    body = _render_groups(items) if items else '<p class="empty">Rien de nouveau depuis la dernière édition.</p>'
    return f'''<section class="category">
  <div class="cat-head">
    <span class="cat-icon">{icon}</span>
    <h2>{esc(label)}</h2>
    <span class="cat-hint">{esc(hint)}</span>
  </div>
  {body}
</section>'''


def build_html(page_date: str, items: list[dict], sidebar_html: str) -> str:
    items = [dict(i, category=classify(i)) for i in items]
    by_cat: dict[str, list[dict]] = {}
    for i in items:
        by_cat.setdefault(i["category"], []).append(i)

    reg_items = [i for i in items if i["category"] in REGULATION_CATEGORIES]
    hw_items = [i for i in items if i["category"] in HARDWARE_CATEGORIES]
    other_items = by_cat.get("hors_perimetre", [])

    def count(lst):
        c = {k: 0 for k in CRITICALITY_ORDER}
        for i in lst:
            c[i["criticality"]] += 1
        return c

    reg_c, hw_c = count(reg_items), count(hw_items)

    # Zone 1 : toutes les rubriques réglementaires sont toujours affichées,
    # même vides, pour qu'on voie d'un coup d'œil ce qui a été couvert.
    zone1 = "".join(
        _render_section(icon, label, hint, by_cat.get(key, []))
        for key, (icon, label, hint) in REGULATION_CATEGORIES.items()
    )
    # Zone 2 : seulement les équipements qui ont une actualité.
    zone2_sections = [
        _render_section(icon, label, hint, by_cat[key])
        for key, (icon, label, hint) in HARDWARE_CATEGORIES.items()
        if by_cat.get(key)
    ]
    zone2 = "".join(zone2_sections) or '<p class="empty">Aucune actualité sur le matériel du projet depuis la dernière édition.</p>'

    other_html = ""
    if other_items:
        icon, label = OTHER_CATEGORY
        other_html = f'''<details class="out-of-scope">
  <summary><span class="cat-icon">{icon}</span><span class="oos-label">{esc(label)}</span><span class="oos-count">{len(other_items)}</span></summary>
  <div class="oos-body">{_render_groups(other_items)}</div>
</details>'''

    seen: dict[str, str] = {}
    for i in items:
        if i["source"] and i["source"] not in seen:
            seen[i["source"]] = i["url"]
    footer_html = (
        '<footer><div class="sources"><span class="sources-label">Sources consultées&nbsp;:</span>'
        + "".join(f'<a href="{esc(u)}" target="_blank" rel="noopener noreferrer">{esc(n)}</a>' for n, u in seen.items())
        + "</div></footer>"
        if seen else ""
    )

    hw_names = ", ".join(v[2] for v in HARDWARE_CATEGORIES.values())

    return f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex">
<title>Veille projet — {esc(page_date)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;650;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
  :root {{
    color-scheme: light;
    --bg: #f5f6f8;
    --surface: #ffffff;
    --surface-2: #fafbfc;
    --border: #e2e5ea;
    --text: #14181f;
    --text-muted: #4b5563;
    --text-faint: #8a93a3;
    --accent: #2f5fd6;
    --accent-soft: #eaf0fd;
    --crit: #e02424;
    --crit-bg: #fbebe9;
    --crit-border: #f0c4bd;
    --imp: #b5730f;
    --imp-bg: #fbf1e1;
    --imp-border: #f0d6a8;
    --info: #2f7a4f;
    --info-bg: #e9f5ee;
    --info-border: #c3e3d1;
    --shadow: 0 2px 10px rgba(20,24,31,.06);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .layout {{
    display: grid;
    grid-template-columns: 190px 1fr;
    grid-template-areas: "side head" "side main";
    gap: 8px 40px;
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 20px 64px;
  }}
  header.page {{ grid-area: head; margin-bottom: 32px; }}
  .content {{ grid-area: main; }}
  aside.sidebar {{ grid-area: side; min-width: 0; }}
  .sidebar-scroll {{
    position: sticky;
    top: 24px;
    max-height: calc(100vh - 48px);
    overflow-y: auto;
    padding-right: 4px;
  }}
  .sidebar-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: var(--text-faint);
    margin-bottom: 10px;
    padding-left: 10px;
  }}
  .sidebar-label-secondary {{ margin-top: 22px; }}
  .day-list {{ display: flex; flex-direction: column; gap: 4px; }}
  .day-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: 8px;
    text-decoration: none;
    color: var(--text-muted);
    font-size: .85rem;
    border: 1px solid transparent;
  }}
  .day-item .day-name {{
    text-transform: uppercase;
    font-size: .72rem;
    letter-spacing: .03em;
    width: 2.4em;
    color: inherit;
  }}
  .day-item .day-num {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-weight: 600; color: var(--text); }}
  .day-item:hover {{ background: var(--surface-2); }}
  .day-item.active {{ background: var(--accent-soft); border-color: var(--accent); color: var(--accent); }}
  .day-item.active .day-num {{ color: var(--accent); }}
  .day-dot {{ width: 6px; height: 6px; border-radius: 50%; background: var(--accent); margin-left: auto; }}
  .week-groups {{ display: flex; flex-direction: column; gap: 2px; }}
  details.week-group {{ font-size: .8rem; }}
  details.week-group summary {{
    cursor: pointer;
    list-style: none;
    padding: 7px 10px;
    border-radius: 8px;
    color: var(--text-faint);
    font-size: .74rem;
    line-height: 1.35;
  }}
  details.week-group summary::-webkit-details-marker {{ display: none; }}
  details.week-group summary:hover {{ background: var(--surface-2); color: var(--text-muted); }}
  details.week-group summary::before {{ content: "▸ "; }}
  details.week-group[open] summary::before {{ content: "▾ "; }}
  .day-list-secondary {{ margin: 2px 0 6px 10px; }}
  .eyebrow {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .78rem;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--accent);
    font-weight: 600;
    margin-bottom: 10px;
  }}
  h1 {{ font-size: 1.9rem; font-weight: 650; margin: 0 0 10px; letter-spacing: -.01em; }}
  .scope-note {{ color: var(--text-muted); font-size: .95rem; line-height: 1.55; max-width: 720px; margin: 0; }}
  .scope-note strong {{ color: var(--text); }}
  .counters {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 28px 0 36px; }}
  .counter {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--text-faint);
    border-radius: 10px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
  }}
  .counter .n {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-variant-numeric: tabular-nums;
    font-size: 1.7rem;
    font-weight: 600;
    display: block;
  }}
  .counter .l {{
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-muted);
  }}
  .counter.crit {{ border-left-color: var(--crit); }}
  .counter.imp {{ border-left-color: var(--imp); }}
  .counter.info {{ border-left-color: var(--info); }}
  section.category {{ margin-bottom: 36px; }}
  .cat-head {{
    display: flex;
    align-items: center;
    gap: 10px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 16px;
  }}
  .cat-icon {{ font-size: 1.2rem; }}
  .cat-head h2 {{ font-size: 1.15rem; font-weight: 600; margin: 0; }}
  .subgroup {{ margin-bottom: 18px; }}
  .subgroup-title {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .78rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
    margin-bottom: 8px;
  }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }}
  .card {{
    display: block;
    text-decoration: none;
    color: inherit;
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--text-faint);
    border-radius: 10px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
    transition: transform .12s ease, box-shadow .12s ease;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 6px 18px rgba(20,24,31,.12); }}
  .card.crit {{ border-left-color: var(--crit); }}
  .card.imp {{ border-left-color: var(--imp); }}
  .card.info {{ border-left-color: var(--info); }}
  .card-top {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }}
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .7rem;
    font-weight: 600;
    letter-spacing: .03em;
    padding: 3px 9px;
    border-radius: 999px;
    border: 1px solid;
  }}
  .badge.crit {{ background: var(--crit-bg); border-color: var(--crit-border); color: var(--crit); }}
  .badge.imp {{ background: var(--imp-bg); border-color: var(--imp-border); color: var(--imp); }}
  .badge.info {{ background: var(--info-bg); border-color: var(--info-border); color: var(--info); }}
  .level1 {{ font-size: 1rem; font-weight: 600; line-height: 1.4; }}
  .card:hover .level1 {{ color: var(--accent); text-decoration: underline; }}
  .level2 {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); }}
  .level2-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .68rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
    margin-bottom: 4px;
  }}
  .meta {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .72rem;
    color: var(--text-faint);
    margin-bottom: 4px;
  }}
  .tech {{ margin: 0; font-size: .85rem; color: var(--text-muted); line-height: 1.5; }}
  .empty {{ color: var(--text-muted); font-style: italic; }}
  details.out-of-scope {{
    margin: 40px 0 8px;
    border-top: 1px solid var(--border);
    padding-top: 20px;
  }}
  details.out-of-scope summary {{
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    list-style: none;
    color: var(--text-faint);
    user-select: none;
  }}
  details.out-of-scope summary::-webkit-details-marker {{ display: none; }}
  details.out-of-scope summary::before {{
    content: "▸";
    font-size: .8rem;
    transition: transform .12s ease;
  }}
  details.out-of-scope[open] summary::before {{ transform: rotate(90deg); }}
  details.out-of-scope .oos-label {{
    font-size: .85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .03em;
  }}
  details.out-of-scope .oos-count {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .75rem;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 8px;
  }}
  details.out-of-scope .oos-body {{ margin-top: 20px; opacity: .85; }}
  footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); }}
  .sources {{ display: flex; flex-wrap: wrap; gap: 6px 14px; align-items: baseline; }}
  .sources-label {{
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    color: var(--text-faint);
  }}
  .sources a {{ font-size: .82rem; color: var(--accent); text-decoration: none; }}
  .sources a:hover {{ text-decoration: underline; }}
  @media (max-width: 860px) {{
    .layout {{
      grid-template-columns: 1fr;
      grid-template-areas: "head" "side" "main";
      gap: 16px 0;
      padding: 24px 16px 48px;
    }}
    .sidebar-label {{ padding-left: 2px; }}
    .sidebar-scroll {{ position: static; max-height: none; overflow: visible; padding-right: 0; }}
    .day-list:not(.day-list-secondary) {{
      flex-direction: row;
      overflow-x: auto;
      gap: 8px;
      padding-bottom: 4px;
      -webkit-overflow-scrolling: touch;
    }}
    .day-list:not(.day-list-secondary) .day-item {{ flex: 0 0 auto; flex-direction: column; text-align: center; padding: 8px 14px; gap: 2px; }}
    .day-list:not(.day-list-secondary) .day-item .day-name {{ width: auto; }}
    .day-list:not(.day-list-secondary) .day-dot {{ margin: 0 auto; }}
  }}
  .zone {{ border-radius: 14px; padding: 22px 22px 6px; margin-bottom: 28px; border: 1px solid var(--border); background: var(--surface); box-shadow: var(--shadow); }}
  .zone-reg {{ border: 2px solid var(--accent); background: linear-gradient(180deg, var(--accent-soft), var(--surface) 140px); }}
  .zone-hw {{ background: var(--surface-2); }}
  .zone-head {{ display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 14px; margin-bottom: 22px; }}
  .zone-kicker {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; color: var(--accent); font-weight: 600; }}
  .zone-title {{ font-size: 1.45rem; font-weight: 650; flex: 1 1 auto; }}
  .zone-hw .zone-title {{ font-size: 1.2rem; }}
  .zone-counts {{ display: flex; gap: 6px; }}
  .pill {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: .75rem; padding: 2px 9px; border-radius: 999px; border: 1px solid; }}
  .pill.crit {{ background: var(--crit-bg); border-color: var(--crit-border); color: var(--crit); }}
  .pill.imp {{ background: var(--imp-bg); border-color: var(--imp-border); color: var(--imp); }}
  .pill.info {{ background: var(--info-bg); border-color: var(--info-border); color: var(--info); }}
  .cat-hint {{ font-size: .78rem; color: var(--text-faint); margin-left: auto; }}
  .legend {{ font-size: .8rem; color: var(--text-muted); margin: 4px 0 8px; }}
  .cve-link {{ font-size: .82rem; color: var(--text-muted); margin-top: 18px; }}
  .cve-link a {{ color: var(--accent); }}
  @media (max-width: 860px) {{ .zone {{ padding: 16px 14px 4px; }} .cat-hint {{ display: none; }} }}
</style>
</head>
<body>
<div class="layout">
{sidebar_html}
<header class="page">
  <div class="eyebrow">Veille projet · quotidienne · {esc(page_date)}</div>
  <h1>Veille réglementaire &amp; matériel</h1>
  <p class="scope-note">D'abord <strong>la réglementation</strong> qui encadre le projet (RGPD, RSE, télécoms), puis <strong>le suivi du matériel</strong> ({esc(hw_names)}) : fins de support, nouvelles versions, compatibilité. Les failles de sécurité urgentes restent sur la veille CVE quotidienne.</p>
</header>
<div class="content">
<div class="zone zone-reg">
  <div class="zone-head">
    <div class="zone-kicker">Zone 1</div>
    <div class="zone-title">⚖️ Réglementation</div>
    <div class="zone-counts"><span class="pill crit">🔴 {reg_c["critique"]}</span><span class="pill imp">🟠 {reg_c["important"]}</span><span class="pill info">🟢 {reg_c["info"]}</span></div>
  </div>
  {zone1}
</div>
<div class="zone zone-hw">
  <div class="zone-head">
    <div class="zone-kicker">Zone 2</div>
    <div class="zone-title">🛠️ Suivi du matériel</div>
    <div class="zone-counts"><span class="pill crit">🔴 {hw_c["critique"]}</span><span class="pill imp">🟠 {hw_c["important"]}</span><span class="pill info">🟢 {hw_c["info"]}</span></div>
  </div>
  {zone2}
</div>
<div class="legend">🔴 Action requise · 🟠 À surveiller · 🟢 Pour info</div>
{other_html}
{footer_html}
<p class="cve-link">Failles de sécurité du jour : <a href="https://dailyreport.pmit.fr/">dailyreport.pmit.fr</a></p>
</div>
</div>
</body>
</html>'''


def sanity_check(rendered: str) -> None:
    if "<!doctype html" not in rendered.lower() or len(rendered) < 400:
        raise RuntimeError("Page générée invalide — publication annulée.")


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    output_dir = os.environ.get("OUTPUT_DIR", "public")
    archive_dir = os.environ.get("ARCHIVE_DIR", "data")
    try:
        data = fetch_items_from_sharepoint()
        page_date = _truncate(str(data.get("date", "")), 40)
        items = sanitize_items(data["items"])
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR pendant la récupération du rapport : {exc}", file=sys.stderr)
        return 1

    current = paris_today()
    if not page_date:
        page_date = day_label(current)
    try:
        save_archive(archive_dir, current, page_date, items)
        weeks = all_archive_weeks(archive_dir)

        index_html = build_html(page_date, items, build_sidebar(weeks, current, current, "root"))
        sanity_check(index_html)
        _write_file(os.path.join(output_dir, "index.html"), index_html)

        for w in weeks:
            archived = load_archive(archive_dir, w)
            if archived is None:
                continue
            page = build_html(archived["page_date"], archived["items"], build_sidebar(weeks, current, w, "archive"))
            _write_file(os.path.join(output_dir, "archive", f"{w.isoformat()}.html"), page)
    except Exception as exc:  # noqa: BLE001
        print(f"ERREUR en générant les pages : {exc}", file=sys.stderr)
        return 1

    print(f"Édition publiée : {os.path.join(output_dir, 'index.html')} ({len(weeks)} jour(s) archivé(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
