# Veille projet — projet.pmit.fr

Page de veille **quotidienne** (jours ouvrés) du projet de déménagement, publiée sur GitHub Pages.
Dépôt séparé de `veille-auto-publish` (page CVE quotidienne) : une panne ici ne touche jamais `dailyreport.pmit.fr`.

## Comment ça marche

1. **Chaque jour ouvré à 8 h 20 (Paris)**, une tâche planifiée Claude cherche les actualités et écrit `veille-projet-items.json` sur le site SharePoint *Veillepublication* (même site que la veille CVE).
2. **À 8 h 05 UTC**, le workflow GitHub lit ce fichier (même app Azure, lecture seule), le vérifie, génère la page et l'archive dans `data/`.
3. GitHub Pages publie la page sur `projet.pmit.fr`.

La page a deux zones :

| Zone | Contenu |
| --- | --- |
| 1 — Réglementation (en tête) | RGPD (CNIL), RSE et numérique responsable (RGESN), télécoms (Arcep) |
| 2 — Suivi du matériel | Fortinet, Unifi, Synology, Veeam, Maxhub : fins de support, versions, compatibilité |

Niveaux : 🔴 action requise · 🟠 à surveiller · 🟢 pour info.

**Page publique** : aucune information confidentielle sur le client (nom, adresse, plans, prestataires).

## Mise en place (une seule fois)

1. **Secrets** (Settings → Secrets and variables → Actions → *Secrets*) : copier depuis `veille-auto-publish` les 3 secrets `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
2. **Variable** (même écran, onglet *Variables*) : `SHAREPOINT_DRIVE_ID`, même valeur que dans `veille-auto-publish`.
3. **Pages** (Settings → Pages) : *Source* = **GitHub Actions** ; *Custom domain* = `projet.pmit.fr`, puis cocher *Enforce HTTPS* dès que possible.
4. **DNS** de `pmit.fr` : ajouter `projet  CNAME  pmit-fr.github.io.`
5. **Premier test** : Actions → *Veille projet* → *Run workflow* (une fois le fichier JSON présent sur SharePoint).

## Format du fichier JSON

```json
{
  "date": "Jeudi 15 octobre 2026",
  "items": [
    {
      "category": "rgpd | rse | telecom | routeur | wifi | nas | sauvegarde | visio | hors_perimetre",
      "product": "CNIL",
      "criticality": "critique | important | info",
      "impact": "Une phrase simple sur ce que ça change.",
      "technical_detail": "Détail optionnel.",
      "source": "CNIL",
      "date": "16/10/2026",
      "url": "https://www.cnil.fr/..."
    }
  ]
}
```

Pour le matériel, c'est le **nom du produit** qui décide de la rubrique (liste `HARDWARE_KEYWORDS` dans `publish_projet.py`) : un produit inconnu part dans « Autres actualités ».
