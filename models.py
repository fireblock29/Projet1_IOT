"""
Couche de persistance JSON pour les données CVE enrichies.
"""

import json
import os
import logging

from config import DATA_DIR, DATA_FILE

logger = logging.getLogger(__name__)


def ensure_data_dir():
    """Crée le répertoire data/ s'il n'existe pas."""
    os.makedirs(DATA_DIR, exist_ok=True)


def load_data():
    """
    Charge les données CVE depuis le fichier JSON.
    Retourne une liste de dictionnaires CVE enrichis.
    """
    ensure_data_dir()
    if not os.path.exists(DATA_FILE):
        logger.info("Fichier de données introuvable, retour d'une liste vide.")
        return []

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Données chargées : %d CVE", len(data))
        return data
    except (json.JSONDecodeError, IOError) as e:
        logger.error("Erreur de lecture des données : %s", e)
        return []


def save_data(cve_list):
    """
    Sauvegarde la liste des CVE enrichies dans le fichier JSON.
    """
    ensure_data_dir()
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(cve_list, f, ensure_ascii=False, indent=2)
        logger.info("Données sauvegardées : %d CVE", len(cve_list))
    except IOError as e:
        logger.error("Erreur d'écriture des données : %s", e)


def get_cve_by_id(cve_id):
    """Recherche un CVE par son identifiant."""
    data = load_data()
    for cve in data:
        if cve.get("id") == cve_id:
            return cve
    return None


def get_statistics(data=None):
    """Calcule des statistiques globales sur les CVE."""
    if data is None:
        data = load_data()

    if not data:
        return {
            "total": 0,
            "critique": 0,
            "eleve": 0,
            "moyen": 0,
            "faible": 0,
            "kev_count": 0,
            "avg_cvss": 0.0,
            "avg_epss": 0.0,
        }

    total = len(data)
    critique = sum(1 for c in data if c.get("severity") == "CRITIQUE")
    eleve = sum(1 for c in data if c.get("severity") == "ÉLEVÉ")
    moyen = sum(1 for c in data if c.get("severity") == "MOYEN")
    faible = sum(1 for c in data if c.get("severity") == "FAIBLE")
    kev_count = sum(1 for c in data if c.get("kev"))
    avg_cvss = sum(c.get("cvss_score", 0) for c in data) / total if total else 0
    avg_epss = sum(c.get("epss_score", 0) for c in data) / total if total else 0

    return {
        "total": total,
        "critique": critique,
        "eleve": eleve,
        "moyen": moyen,
        "faible": faible,
        "kev_count": kev_count,
        "avg_cvss": round(avg_cvss, 2),
        "avg_epss": round(avg_epss, 4),
    }
