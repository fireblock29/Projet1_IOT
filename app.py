"""
Application Flask — Plateforme de Priorisation IoT.
Interface web pour visualiser, filtrer et prioriser les vulnérabilités CVE.
"""

import logging
import threading

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG
from models import load_data, get_cve_by_id, get_statistics
from prioritizer import get_mitigation_details

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("app")

app = Flask(__name__)
app.secret_key = "iot-priorisation-secret-key-2026"


@app.route("/")
def dashboard():
    """Page principale — Tableau de bord avec recherche, filtres et tri."""
    data = load_data()

    # --- Recherche ---
    search = request.args.get("search", "").strip()
    if search:
        search_lower = search.lower()
        data = [
            cve for cve in data
            if search_lower in cve.get("id", "").lower()
            or search_lower in cve.get("description", "").lower()
        ]

    # --- Filtre par sévérité ---
    severity_filter = request.args.get("severity", "").strip()
    if severity_filter:
        data = [cve for cve in data if cve.get("severity") == severity_filter]

    # --- Filtre KEV uniquement ---
    kev_only = request.args.get("kev_only", "").strip()
    if kev_only == "1":
        data = [cve for cve in data if cve.get("kev")]

    # --- Tri ---
    sort_by = request.args.get("sort", "risk_score")
    sort_order = request.args.get("order", "desc")
    reverse = sort_order == "desc"

    sort_keys = {
        "risk_score": lambda c: c.get("risk_score", 0),
        "cvss": lambda c: c.get("cvss_score", 0),
        "epss": lambda c: c.get("epss_score", 0),
        "id": lambda c: c.get("id", ""),
    }

    key_func = sort_keys.get(sort_by, sort_keys["risk_score"])
    data.sort(key=key_func, reverse=reverse)

    # --- Statistiques ---
    all_data = load_data()
    stats = get_statistics(all_data)

    return render_template(
        "dashboard.html",
        cves=data,
        stats=stats,
        search=search,
        severity_filter=severity_filter,
        kev_only=kev_only,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@app.route("/cve/<cve_id>")
def detail(cve_id):
    """Fiche détaillée d'une vulnérabilité."""
    cve = get_cve_by_id(cve_id)
    if not cve:
        flash(f"CVE {cve_id} introuvable.", "error")
        return redirect(url_for("dashboard"))

    mitigations = get_mitigation_details(cve)

    return render_template(
        "detail.html",
        cve=cve,
        mitigations=mitigations,
    )


@app.route("/sync", methods=["POST"])
def sync():
    """Lance la synchronisation des CVE en arrière-plan."""
    def _run_sync():
        try:
            from collector import run_sync
            run_sync()
        except Exception as e:
            logger.error("Erreur lors de la synchronisation : %s", e)

    thread = threading.Thread(target=_run_sync, daemon=True)
    thread.start()
    flash("Synchronisation lancée en arrière-plan. Actualisez la page dans quelques minutes.", "info")
    return redirect(url_for("dashboard"))


@app.route("/api/stats")
def api_stats():
    """Endpoint API pour les statistiques (usage interne)."""
    stats = get_statistics()
    return jsonify(stats)


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
