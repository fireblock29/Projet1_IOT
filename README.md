# IoT Shield — Plateforme de Priorisation des Vulnérabilités IoT

Plateforme web de collecte, d'enrichissement et de priorisation des vulnérabilités (CVE) affectant les **routeurs Cisco**, basée sur les données ouvertes NVD, EPSS et KEV.

## Fonctionnalités

- **Collecte automatique** des CVE depuis l'API NVD (NIST)
- **Enrichissement** avec les scores EPSS (probabilité d'exploitation) et le catalogue KEV (CISA)
- **Score de Risque Global** pondéré : CVSS (40%) + EPSS (35%) + KEV (25%)
- **Justification textuelle** de chaque niveau de risque
- **Mesures de mitigation** concrètes adaptées aux CWE détectées
- **Références de conformité** ETSI EN 303 645 et NISTIR 8259A
- **Interface web** moderne avec recherche, filtres et tri

## Architecture

```
ProjetIoT/
├── app.py              # Serveur Flask (routes, vues)
├── config.py           # Configuration et constantes
├── api_clients.py      # Clients API (NVD, EPSS, KEV)
├── collector.py        # Script de synchronisation
├── prioritizer.py      # Moteur de priorisation
├── models.py           # Persistance JSON
├── requirements.txt    # Dépendances Python
├── Dockerfile          # Conteneurisation
├── data/               # Stockage local des CVE
│   └── cve_data.json
├── static/
│   └── style.css       # Design dark mode
└── templates/
    ├── base.html       # Layout de base
    ├── dashboard.html  # Tableau de bord
    └── detail.html     # Fiche détaillée CVE
```

## Installation et Lancement

### Prérequis
- Python 3.9+
- pip

### Installation locale

```bash
# Cloner et entrer dans le projet
cd ProjetIoT

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'application
python app.py
```

L'application sera accessible sur **http://localhost:5000**.
Si le port est déjà pris et nécessite d'être modifié, cela se fait directement dans le fichier `config.py`, ligne 45 : `FLASK_PORT = 5000`. 

### Collecte des données

```bash
# Première synchronisation (récupère les CVE depuis les APIs)
python collector.py
```

> **Note** : La collecte peut prendre plusieurs minutes en raison du rate limiting de l'API NVD (6 sec entre les requêtes sans clé API).

### Clé API NVD (optionnel)

Pour accélérer la collecte, vous pouvez obtenir une clé API gratuite sur [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) :

```bash
export NVD_API_KEY="votre-clé-api"
python collector.py
```

### Avec Docker

```bash
# Construire l'image
docker build -t iot-shield .

# Lancer le conteneur
docker run -p 5000:5000 iot-shield #À adapter si le port est modifié
```

## Score de Risque Global

Le score est calculé selon la formule :

| Facteur | Poids | Source | Description |
|---------|-------|--------|-------------|
| CVSS | 40% | NVD (NIST) | Impact technique (0–10) |
| EPSS | 35% | FIRST | Probabilité d'exploitation à 30 jours (0–1 → normalisé 0–10) |
| KEV | 25% | CISA | Bonus exploitation active (+10 si présent) |

**Niveaux de sévérité** :
- **Critique** : Score ≥ 8.0
- **Élevé** : Score ≥ 6.0
- **Moyen** : Score ≥ 4.0
- **Faible** : Score < 4.0

## Conformité

Les recommandations intègrent les standards :
- **ETSI EN 303 645** — Cybersécurité pour les dispositifs IoT grand public
- **NISTIR 8259A** — Capacités de cybersécurité de base pour les appareils IoT

## Sources de données

| Source | URL | Données |
|--------|-----|---------|
| NVD (NIST) | https://nvd.nist.gov/ | CVE, CVSS, CWE |
| EPSS (FIRST) | https://www.first.org/epss/ | Probabilité d'exploitation |
| KEV (CISA) | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Exploitations actives |
