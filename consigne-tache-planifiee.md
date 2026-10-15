# Consigne de la tâche planifiée « Veille projet »

À coller comme consigne d'une tâche planifiée Claude, **chaque lundi à 7 h 00 (heure de Paris)**, comme la tâche « Daily report ».

---

Tu prépares la veille hebdomadaire d'un projet informatique de déménagement de bureaux. Couvre les 7 derniers jours.

**Zone 1 — Réglementation** (priorité) :
- `rgpd` : décisions, sanctions, recommandations de la CNIL et du CEPD utiles à une entreprise (sécurité des données, effacement de matériel, sauvegardes, visioconférence, Wi-Fi invité). Sources : cnil.fr, edpb.europa.eu.
- `rse` : numérique responsable, RGESN, recyclage du matériel (DEEE), durée de vie des équipements, accessibilité. Sources : ecoresponsable.numerique.gouv.fr, ecologie.gouv.fr, arcep.fr (rubrique environnement).
- `telecom` : fibre et accès internet pour les entreprises, opérateurs, fermeture du réseau cuivre. Source : arcep.fr.

**Zone 2 — Matériel du projet** (hors failles de sécurité, déjà couvertes par la veille CVE quotidienne) : fins de support, fins de vie, nouvelles versions majeures, problèmes de compatibilité connus.
- `routeur` : Fortinet (FortiGate, FortiOS)
- `wifi` : Ubiquiti UniFi
- `nas` : Synology (DSM)
- `sauvegarde` : Veeam
- `visio` : Maxhub (y compris compatibilité Microsoft Teams et Google Meet)
Sources : sites officiels des fabricants en priorité.

**Règles strictes :**
- Ouvre chaque page avant de la citer ; un extrait de moteur de recherche ne suffit pas. Ne garde que ce que la page dit vraiment.
- Pas de doublon, pas d'actualité de plus de 7 jours, pas de rumeur.
- Le résultat sera publié sur une **page publique** : n'écris jamais de nom de client, d'adresse, de plan ou de prestataire.
- Le champ `product` doit contenir le nom du fabricant ou de l'organisme (ex. « Synology DSM 7.2 », « CNIL »).
- `criticality` : `critique` = une action est nécessaire pour le projet ; `important` = à surveiller ; `info` = pour information.
- `impact` : une phrase simple, compréhensible par un non-spécialiste.
- S'il n'y a rien pour une rubrique, n'invente rien.

**Sortie :** écris un fichier `veille-projet-items.json` (UTF-8, JSON valide uniquement) dans la bibliothèque *Documents partagés* du site SharePoint **Veillepublication**, en remplaçant la version précédente, au format :

```json
{
  "date": "Semaine du <date du lundi en français>",
  "items": [
    {
      "category": "rgpd",
      "product": "CNIL",
      "criticality": "important",
      "impact": "…",
      "technical_detail": "…",
      "source": "CNIL",
      "date": "JJ/MM/AAAA",
      "url": "https://…"
    }
  ]
}
```
