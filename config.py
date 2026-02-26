"""
Configuration de la Plateforme de Priorisation IoT.
Constantes, URLs des APIs, pondérations du score de risque.
"""

import os

# === Répertoires ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATA_FILE = os.path.join(DATA_DIR, "cve_data.json")

# === Périmètre : Routeurs ===
KEYWORD_SEARCH = "router"
CPE_MATCH_STRING = "cpe:2.3:h:*:router:*"

# === API NVD (NIST) ===
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # Optionnel, mais augmente le rate limit
NVD_RESULTS_PER_PAGE = 50
NVD_REQUEST_DELAY = 6.0  # Secondes entre les requêtes (sans clé API)
NVD_REQUEST_DELAY_WITH_KEY = 0.6  # Avec clé API

# === API EPSS (FIRST) ===
EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# === Catalogue KEV (CISA) ===
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# === Pondérations du Score de Risque Global ===
WEIGHT_CVSS = 0.40   # 40% — Impact technique
WEIGHT_EPSS = 0.35   # 35% — Probabilité d'exploitation
WEIGHT_KEV = 0.25    # 25% — Exploitation active confirmée

# === Seuils de sévérité ===
SEVERITY_THRESHOLDS = {
    "CRITIQUE": 8.0,
    "ÉLEVÉ": 6.0,
    "MOYEN": 4.0,
    "FAIBLE": 0.0,
}

# === Flask ===
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

# === Nombre max de CVE à collecter ===
MAX_CVE_FETCH = 200
