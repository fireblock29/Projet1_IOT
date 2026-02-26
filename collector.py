"""
Script de synchronisation des CVE — Worker de collecte.
Récupère les CVE liées aux routeurs, enrichit les données
avec CVSS, EPSS et KEV, puis sauvegarde localement.
"""

import sys
import logging

from api_clients import NVDClient, EPSSClient, KEVClient
from prioritizer import calculate_risk_score, generate_justification, get_severity
from models import load_data, save_data

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("collector")


def run_sync():
    """
    Exécute le pipeline complet de collecte et enrichissement.
    1. Récupérer les CVE depuis NVD
    2. Enrichir avec les scores EPSS
    3. Vérifier le catalogue KEV
    4. Calculer les scores de risque
    5. Sauvegarder en local
    """
    logger.info("=" * 60)
    logger.info("DÉMARRAGE DE LA SYNCHRONISATION")
    logger.info("=" * 60)

    # --- Étape 1 : Collecte NVD ---
    logger.info("Étape 1/5 : Collecte des CVE depuis NVD...")
    nvd = NVDClient()
    cves = nvd.fetch_cves()

    if not cves:
        logger.warning("Aucune CVE récupérée depuis NVD. Arrêt.")
        return 0

    logger.info("→ %d CVE récupérées", len(cves))

    # --- Étape 2 : Enrichissement EPSS ---
    logger.info("Étape 2/5 : Récupération des scores EPSS...")
    epss = EPSSClient()
    cve_ids = [c["id"] for c in cves]
    epss_scores = epss.get_scores(cve_ids)

    for cve in cves:
        epss_data = epss_scores.get(cve["id"], {})
        cve["epss_score"] = epss_data.get("epss", 0.0)
        cve["epss_percentile"] = epss_data.get("percentile", 0.0)

    enriched_epss = sum(1 for c in cves if c["epss_score"] > 0)
    logger.info("→ %d/%d CVE enrichies avec EPSS", enriched_epss, len(cves))

    # --- Étape 3 : Vérification KEV ---
    logger.info("Étape 3/5 : Vérification du catalogue KEV...")
    kev = KEVClient()
    kev_results = kev.check_cves(cve_ids)

    for cve in cves:
        kev_data = kev_results.get(cve["id"], {})
        cve["kev"] = kev_data.get("kev", False)
        cve["kev_date_added"] = kev_data.get("date_added", "")

    kev_count = sum(1 for c in cves if c["kev"])
    logger.info("→ %d CVE présentes dans le catalogue KEV", kev_count)

    # --- Étape 4 : Calcul des scores de risque ---
    logger.info("Étape 4/5 : Calcul des scores de risque...")
    for cve in cves:
        cve["risk_score"] = calculate_risk_score(cve)
        cve["severity"] = get_severity(cve["risk_score"])
        cve["justification"] = generate_justification(cve)

    # --- Étape 5 : Fusion et sauvegarde ---
    logger.info("Étape 5/5 : Sauvegarde des données...")

    # Fusionner avec les données existantes
    existing = load_data()
    existing_ids = {c["id"] for c in existing}
    new_ids = {c["id"] for c in cves}

    # Mettre à jour les CVE existantes, ajouter les nouvelles
    merged = []
    for cve in cves:
        merged.append(cve)
    for cve in existing:
        if cve["id"] not in new_ids:
            merged.append(cve)

    # Trier par score de risque décroissant
    merged.sort(key=lambda c: c.get("risk_score", 0), reverse=True)

    save_data(merged)

    # --- Résumé ---
    new_count = len(new_ids - existing_ids)
    updated_count = len(new_ids & existing_ids)
    logger.info("=" * 60)
    logger.info("SYNCHRONISATION TERMINÉE")
    logger.info("  Total CVE : %d", len(merged))
    logger.info("  Nouvelles : %d", new_count)
    logger.info("  Mises à jour : %d", updated_count)
    logger.info("  Dans KEV : %d", kev_count)
    logger.info("=" * 60)

    return len(merged)


if __name__ == "__main__":
    try:
        count = run_sync()
        logger.info("Terminé avec %d CVE.", count)
    except KeyboardInterrupt:
        logger.info("Interruption utilisateur.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Erreur fatale : %s", e)
        sys.exit(1)
