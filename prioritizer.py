"""
Moteur de Priorisation — Cœur du projet.
Calcule un Score de Risque Global pondéré et génère des justifications textuelles.
Intègre des références de conformité ETSI EN 303 645 et NISTIR 8259A.
"""

from config import WEIGHT_CVSS, WEIGHT_EPSS, WEIGHT_KEV, SEVERITY_THRESHOLDS


def calculate_risk_score(cve):
    """
    Calcule le Score de Risque Global (0–10) à partir de trois facteurs :
      - CVSS (40%) → Impact technique
      - EPSS (35%) → Probabilité d'exploitation (normalisé sur 10)
      - KEV  (25%) → Bonus si activement exploité (10 si KEV, 0 sinon)

    Formule :
      Score = CVSS × 0.40 + (EPSS × 10) × 0.35 + KEV_bonus × 0.25
    """
    cvss = float(cve.get("cvss_score", 0.0))
    epss = float(cve.get("epss_score", 0.0))
    kev = bool(cve.get("kev", False))

    # Normaliser EPSS (0-1) vers une échelle 0-10
    epss_normalized = min(epss * 10, 10.0)

    # Bonus KEV : 10 si activement exploité, 0 sinon
    kev_bonus = 10.0 if kev else 0.0

    score = (cvss * WEIGHT_CVSS) + (epss_normalized * WEIGHT_EPSS) + (kev_bonus * WEIGHT_KEV)

    return round(min(score, 10.0), 2)


def get_severity(risk_score):
    """Détermine le niveau de sévérité à partir du score de risque."""
    for level, threshold in SEVERITY_THRESHOLDS.items():
        if risk_score >= threshold:
            return level
    return "FAIBLE"


def generate_justification(cve):
    """
    Génère une explication textuelle du score de risque.
    Inclut des recommandations contextuelles et des références de conformité.
    """
    cvss = float(cve.get("cvss_score", 0.0))
    epss = float(cve.get("epss_score", 0.0))
    kev = bool(cve.get("kev", False))
    risk_score = float(cve.get("risk_score", 0.0))
    severity = get_severity(risk_score)

    parts = []

    # === Analyse du niveau de risque ===
    if severity == "CRITIQUE":
        parts.append(f"PRIORITÉ CRITIQUE (Score : {risk_score}/10)")
    elif severity == "ÉLEVÉ":
        parts.append(f"PRIORITÉ ÉLEVÉE (Score : {risk_score}/10)")
    elif severity == "MOYEN":
        parts.append(f"PRIORITÉ MOYENNE (Score : {risk_score}/10)")
    else:
        parts.append(f"PRIORITÉ FAIBLE (Score : {risk_score}/10)")

    # === Justification CVSS ===
    if cvss >= 9.0:
        parts.append(f"• Impact critique (CVSS {cvss}/10) : vulnérabilité permettant une compromission totale du système.")
    elif cvss >= 7.0:
        parts.append(f"• Impact élevé (CVSS {cvss}/10) : vulnérabilité pouvant affecter gravement la confidentialité, l'intégrité ou la disponibilité.")
    elif cvss >= 4.0:
        parts.append(f"• Impact modéré (CVSS {cvss}/10) : vulnérabilité exploitable sous certaines conditions.")
    else:
        parts.append(f"• Impact faible (CVSS {cvss}/10) : vulnérabilité à portée limitée.")

    # === Justification KEV ===
    if kev:
        kev_date = cve.get("kev_date_added", "")
        date_info = f" (ajoutée le {kev_date})" if kev_date else ""
        parts.append(f"• EXPLOITATION ACTIVE CONFIRMÉE : Cette CVE figure dans le catalogue KEV de la CISA{date_info}. Des attaques réelles ont été observées.")
    else:
        parts.append("• Aucune exploitation active connue dans le catalogue KEV.")

    # === Justification EPSS ===
    epss_pct = epss * 100
    if epss >= 0.5:
        parts.append(f"• Probabilité d'attaque très élevée (EPSS : {epss_pct:.1f}%) : cette vulnérabilité a une forte chance d'être exploitée dans les 30 prochains jours.")
    elif epss >= 0.1:
        parts.append(f"• Probabilité d'attaque significative (EPSS : {epss_pct:.1f}%) : risque d'exploitation notable à court terme.")
    elif epss >= 0.01:
        parts.append(f"• Probabilité d'attaque modérée (EPSS : {epss_pct:.1f}%) : exploitation possible mais pas imminente.")
    else:
        parts.append(f"• Probabilité d'attaque faible (EPSS : {epss_pct:.1f}%) : exploitation peu probable à court terme.")

    # === Recommandations ===
    parts.append("")
    parts.append("RECOMMANDATIONS :")

    if severity in ("CRITIQUE", "ÉLEVÉ"):
        parts.append("  1. Appliquer le correctif (patch) en urgence si disponible.")
        parts.append("  2. Isoler les équipements affectés par segmentation réseau (VLAN dédié).")
        parts.append("  3. Désactiver les services non essentiels exposés (HTTP, Telnet, SNMP v1/v2).")
        parts.append("  4. Mettre en place une surveillance renforcée (IDS/IPS, journaux Syslog).")
        if kev:
            parts.append("  5. ⚡ ACTION IMMÉDIATE requise : exploitation active détectée.")
    elif severity == "MOYEN":
        parts.append("  1. Planifier l'application du correctif dans un délai raisonnable.")
        parts.append("  2. Vérifier la configuration des ACL et des pare-feux.")
        parts.append("  3. Auditer les accès administratifs (SSH uniquement, MFA recommandé).")
    else:
        parts.append("  1. Inscrire la correction dans le cycle de maintenance standard.")
        parts.append("  2. Documenter la vulnérabilité dans le registre des risques.")

    # === Références de conformité ===
    parts.append("")
    parts.append("CONFORMITÉ :")
    parts.append("  • ETSI EN 303 645 — Exigences de cybersécurité pour les dispositifs IoT grand public :")
    parts.append("    - Provision 5.3 : Les logiciels doivent être mis à jour de manière sécurisée.")
    parts.append("    - Provision 5.1 : Pas de mots de passe par défaut universels.")

    parts.append("  • NISTIR 8259A — Capacités de cybersécurité de base pour les appareils IoT :")
    parts.append("    - Capacité de mise à jour logicielle sécurisée.")
    parts.append("    - Capacité d'identification et de configuration de l'appareil.")
    parts.append("    - Protection des données et contrôle d'accès logique.")

    return "\n".join(parts)


def get_mitigation_details(cve):
    """
    Retourne des mesures de mitigation détaillées selon le type de CVE.
    """
    cvss = float(cve.get("cvss_score", 0.0))
    cwe_list = cve.get("cwe", [])

    mitigations = []

    # Mitigations basées sur les CWE
    cwe_mitigations = {
        "CWE-78": ("Injection de commandes OS",
                    "Valider et assainir toutes les entrées utilisateur. Utiliser des listes blanches pour les commandes autorisées."),
        "CWE-79": ("Cross-Site Scripting (XSS)",
                    "Activer l'encodage des sorties HTML. Configurer les en-têtes CSP (Content-Security-Policy)."),
        "CWE-89": ("Injection SQL",
                    "Utiliser des requêtes paramétrées. Limiter les privilèges des comptes de base de données."),
        "CWE-119": ("Dépassement de tampon",
                     "Appliquer le patch constructeur. Activer ASLR et DEP si supporté. Mettre à jour le firmware."),
        "CWE-120": ("Copie de tampon sans vérification",
                     "Mettre à jour le firmware. Isoler l'appareil sur un segment réseau dédié."),
        "CWE-200": ("Divulgation d'informations",
                     "Désactiver les services d'information inutiles (HTTP info, SNMP public). Restreindre les accès."),
        "CWE-287": ("Authentification incorrecte",
                     "Forcer l'authentification forte (SSH + clés, désactiver Telnet). Changer les identifiants par défaut."),
        "CWE-352": ("Cross-Site Request Forgery (CSRF)",
                     "Implémenter des jetons anti-CSRF. Vérifier l'en-tête Referer."),
        "CWE-400": ("Consommation incontrôlée de ressources",
                     "Configurer des limites de débit (rate limiting). Activer la protection anti-DoS."),
        "CWE-416": ("Utilisation après libération (Use After Free)",
                     "Appliquer le correctif firmware. Surveiller la stabilité du système."),
        "CWE-476": ("Déréférencement de pointeur NULL",
                     "Mettre à jour le firmware vers la dernière version stable."),
        "CWE-787": ("Écriture hors limites",
                     "Appliquer le correctif constructeur en priorité. Segmenter le réseau."),
    }

    for cwe in cwe_list:
        if cwe in cwe_mitigations:
            title, detail = cwe_mitigations[cwe]
            mitigations.append({"cwe": cwe, "title": title, "detail": detail})

    # Mitigations génériques selon la gravité
    if cvss >= 7.0:
        mitigations.append({
            "cwe": "GÉNÉRAL",
            "title": "Mesures d'urgence pour un routeur",
            "detail": (
                "1. Vérifier les mises à jour disponibles.\n"
                "2. Appliquer les ACL pour restreindre l'accès aux interfaces de gestion.\n"
                "3. Désactiver les protocoles non sécurisés (Telnet, HTTP, SNMPv1/v2c).\n"
                "4. Activer le logging vers un serveur Syslog centralisé.\n"
                "5. Implémenter CoPP (Control Plane Policing) pour protéger le plan de contrôle."
            ),
        })

    if not mitigations:
        mitigations.append({
            "cwe": "GÉNÉRAL",
            "title": "Mesures préventives standard",
            "detail": (
                "1. Maintenir le firmware à jour.\n"
                "2. Restreindre l'accès administratif aux réseaux de gestion.\n"
                "3. Activer la journalisation et la surveillance."
            ),
        })

    return mitigations
