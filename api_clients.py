"""
Clients API pour interroger les sources de données de vulnérabilités.
- NVDClient  : API NVD (NIST) — CVE et scores CVSS
- EPSSClient : API EPSS (FIRST) — Probabilité d'exploitation
- KEVClient  : Catalogue KEV (CISA) — Vulnérabilités activement exploitées
"""

import time
import logging
import requests
from datetime import datetime, timedelta, timezone

from config import (
    NVD_API_BASE,
    NVD_API_KEY,
    NVD_RESULTS_PER_PAGE,
    NVD_REQUEST_DELAY,
    NVD_REQUEST_DELAY_WITH_KEY,
    KEYWORD_SEARCH,
    MAX_CVE_FETCH,
    EPSS_API_BASE,
    KEV_URL,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Client NVD (NIST)
# ──────────────────────────────────────────────
class NVDClient:
    """Interroge l'API NVD v2.0 pour récupérer les CVE liées au périmètre."""

    def __init__(self):
        self.base_url = NVD_API_BASE
        self.api_key = NVD_API_KEY
        self.delay = NVD_REQUEST_DELAY_WITH_KEY if self.api_key else NVD_REQUEST_DELAY
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def fetch_cves(self, keyword=None, max_results=None):
        """
        Récupère les CVE depuis l'API NVD avec pagination.
        Retourne une liste de dictionnaires CVE bruts.
        """
        keyword = keyword or KEYWORD_SEARCH
        max_results = max_results or MAX_CVE_FETCH
        all_cves = []
        start_index = 0
        days_back = 3650 

        # Calcul des dates
        now = datetime.now(timezone.utc)

        start_date_obj = now - timedelta(days=120)

        start_date = start_date_obj.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_date = now.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        logger.info("Début de la collecte NVD pour '%s' (max=%d)", keyword, max_results)

        while start_index < max_results:
            params = {
                "keywordSearch": keyword,
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
                "resultsPerPage": min(NVD_RESULTS_PER_PAGE, max_results - start_index),
                "startIndex": start_index,
            }

            try:
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                logger.error("Erreur NVD (startIndex=%d) : %s", start_index, e)
                break

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.info("Plus de résultats à startIndex=%d", start_index)
                break

            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                parsed = self._parse_cve(cve_item)
                if parsed:
                    all_cves.append(parsed)

            total_results = data.get("totalResults", 0)
            start_index += len(vulnerabilities)
            logger.info(
                "  Collecté %d/%d (total API: %d)",
                len(all_cves), max_results, total_results,
            )

            if start_index >= total_results:
                break

            # Rate limiting
            time.sleep(self.delay)

        logger.info("Collecte NVD terminée : %d CVE récupérées", len(all_cves))
        return all_cves

    @staticmethod
    def _parse_cve(cve_item):
        """Extrait les champs utiles d'un objet CVE NVD."""
        cve_id = cve_item.get("id", "")
        if not cve_id:
            return None

        # Description
        descriptions = cve_item.get("descriptions", [])
        description_fr = ""
        description_en = ""
        for desc in descriptions:
            if desc.get("lang") == "fr":
                description_fr = desc.get("value", "")
            elif desc.get("lang") == "en":
                description_en = desc.get("value", "")
        description = description_fr or description_en

        # CVSS — Priorité à v3.1, sinon v3.0, sinon v2.0
        metrics = cve_item.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        cvss_version = ""

        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_version = cvss_data.get("version", version_key)
                break

        # CWE
        weaknesses = cve_item.get("weaknesses", [])
        cwe_list = []
        for w in weaknesses:
            for d in w.get("description", []):
                cwe_id = d.get("value", "")
                if cwe_id and cwe_id != "NVD-CWE-noinfo" and cwe_id != "NVD-CWE-Other":
                    cwe_list.append(cwe_id)

        # Références
        references = [
            ref.get("url", "") for ref in cve_item.get("references", [])
            if ref.get("url")
        ]

        # Date de publication
        published = cve_item.get("published", "")

        return {
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "cwe": cwe_list,
            "references": references[:5],  # Limiter à 5 références
            "published": published,
            "epss_score": 0.0,
            "epss_percentile": 0.0,
            "kev": False,
            "kev_date_added": "",
            "risk_score": 0.0,
            "severity": "",
            "justification": "",
        }


# ──────────────────────────────────────────────
#  Client EPSS (FIRST)
# ──────────────────────────────────────────────
class EPSSClient:
    """Interroge l'API EPSS pour obtenir la probabilité d'exploitation."""

    def __init__(self):
        self.base_url = EPSS_API_BASE
        self.session = requests.Session()

    def get_scores(self, cve_ids):
        """
        Récupère les scores EPSS pour une liste de CVE IDs.
        Retourne un dict {cve_id: {"epss": float, "percentile": float}}.
        """
        if not cve_ids:
            return {}

        results = {}
        # API EPSS accepte jusqu'à 100 CVEs par requête
        batch_size = 100

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            cve_param = ",".join(batch)

            try:
                response = self.session.get(
                    self.base_url,
                    params={"cve": cve_param},
                    timeout=30,
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                logger.error("Erreur EPSS (batch %d) : %s", i, e)
                continue

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                if cve_id:
                    results[cve_id] = {
                        "epss": float(entry.get("epss", 0.0)),
                        "percentile": float(entry.get("percentile", 0.0)),
                    }

            time.sleep(1)  # Rate limiting minimal

        logger.info("Scores EPSS récupérés pour %d CVE", len(results))
        return results


# ──────────────────────────────────────────────
#  Client KEV (CISA)
# ──────────────────────────────────────────────
class KEVClient:
    """Vérifie si des CVE figurent dans le catalogue KEV de la CISA."""

    def __init__(self):
        self.url = KEV_URL
        self._catalog = None

    def _load_catalog(self):
        """Télécharge et met en cache le catalogue KEV."""
        if self._catalog is not None:
            return

        logger.info("Téléchargement du catalogue KEV CISA...")
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            self._catalog = {
                v.get("cveID"): v.get("dateAdded", "")
                for v in vulnerabilities
                if v.get("cveID")
            }
            logger.info("Catalogue KEV chargé : %d entrées", len(self._catalog))
        except requests.exceptions.RequestException as e:
            logger.error("Erreur de chargement KEV : %s", e)
            self._catalog = {}

    def check_cves(self, cve_ids):
        """
        Vérifie si les CVE sont dans le catalogue KEV.
        Retourne un dict {cve_id: {"kev": bool, "date_added": str}}.
        """
        self._load_catalog()
        results = {}
        for cve_id in cve_ids:
            if cve_id in self._catalog:
                results[cve_id] = {
                    "kev": True,
                    "date_added": self._catalog[cve_id],
                }
            else:
                results[cve_id] = {
                    "kev": False,
                    "date_added": "",
                }

        kev_count = sum(1 for r in results.values() if r["kev"])
        logger.info("Vérification KEV : %d/%d dans le catalogue", kev_count, len(cve_ids))
        return results
