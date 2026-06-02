# SP Compliance Classification Engine
# Processes ACL extract data
# Applies risk rules and returns classified results
# Every decision is explainable and auditable

import json
from pathlib import Path

# ── Privilege priority order ──────────────────────────────────────────────────
# Highest risk first — used to determine risk score per login
PRIVILEGE_PRIORITY = [
    "SYSADMIN",
    "SQL SERVER ADMIN",
    "SERVERADMIN",
    "SECURITYADMIN",
    "DB_OWNER",
    "DATABASE ADMIN",
    "DB_DDLADMIN",
    "MODIFY_DATA",
    "DB_DATAWRITER",
    "LOW_PRIVILEGE",
]

# ── Risk weight per privilege summary ─────────────────────────────────────────
PRIVILEGE_RISK = {
    "SYSADMIN":          40,
    "SQL SERVER ADMIN":  40,
    "SERVERADMIN":       35,
    "SECURITYADMIN":     35,
    "DB_OWNER":          30,
    "DATABASE ADMIN":    25,
    "DB_DDLADMIN":       20,
    "MODIFY_DATA":       15,
    "DB_DATAWRITER":     15,
    "LOW_PRIVILEGE":      5,
}

# ── Risk tiers ────────────────────────────────────────────────────────────────
TIER_CRITICAL = "CRITICAL"
TIER_HIGH     = "HIGH"
TIER_MEDIUM   = "MEDIUM"
TIER_LOW      = "LOW"


def load_principals(filepath: str) -> list[dict]:
    """Load raw SP records from a JSON file."""
    path = Path(filepath)
    with open(path, "r") as f:
        return json.load(f)


def get_highest_privilege(role_mappings: list[str]) -> str:
    """
    Given a list of role mappings for one login
    return the highest risk privilege summary
    using the PRIVILEGE_PRIORITY order
    """
    for privilege in PRIVILEGE_PRIORITY:
        if privilege in role_mappings:
            return privilege
    return "LOW_PRIVILEGE"


def classify_principal(sp: dict) -> dict:
    """
    Apply compliance rules to a single SP record.
    Risk score is based on highest role mapping only.
    All role mappings are preserved for reporting.

    Returns the original record plus:
      - highest_privilege: top risk role mapping
      - findings:          list of specific control failures
      - score:             integer 0-100
      - risk_tier:         CRITICAL / HIGH / MEDIUM / LOW
      - recommended_action: plain English next step
    """
    findings = []
    score    = 0

    # ── Get role mappings for this login ──────────────────────────────────────
    role_mappings    = sp.get("role_mappings", [])
    highest_privilege = get_highest_privilege(role_mappings)

    # ── RULE 1: Score based on highest privilege ──────────────────────────────
    privilege_score = PRIVILEGE_RISK.get(highest_privilege, 5)
    score += privilege_score
    if privilege_score >= 35:
        findings.append(
            f"Critical privilege assigned: {highest_privilege}"
        )
    elif privilege_score >= 25:
        findings.append(
            f"Elevated privilege assigned: {highest_privilege}"
        )

    # ── RULE 2: Login is disabled but still exists ────────────────────────────
    if sp.get("login_enabled", "YES").upper() == "NO":
        findings.append("Login is disabled but account still exists")
        score += 15

    # ── RULE 3: Non-interactive account with high privilege ───────────────────
    if (sp.get("interactive", "YES").upper() == "NO"
            and privilege_score >= 25):
        findings.append(
            "Non-interactive account holds elevated privilege"
        )
        score += 20

    # ── RULE 4: Windows Group with high privilege ─────────────────────────────
    if (sp.get("principal_type", "") == "Windows Group"
            and privilege_score >= 25):
        findings.append(
            "Windows Group assigned elevated privilege — "
            "membership not directly auditable"
        )
        score += 15

    # ── RULE 5: Dev/test account in production instance ───────────────────────
    principal_name = sp.get("principal_name", "").lower()
    if any(kw in principal_name
           for kw in ["dev", "test", "uat", "staging"]):
        findings.append(
            "Dev/test account name detected on production instance"
        )
        score += 20

    # ── RULE 6: Multiple high privilege role mappings ─────────────────────────
    high_priv_count = sum(
        1 for rm in role_mappings
        if PRIVILEGE_RISK.get(rm, 0) >= 25
    )
    if high_priv_count > 1:
        findings.append(
            f"Multiple elevated privileges assigned: "
            f"{high_priv_count} high-risk role mappings"
        )
        score += 10

    # ── Determine risk tier from score ────────────────────────────────────────
    if score >= 70:
        risk_tier = TIER_CRITICAL
    elif score >= 45:
        risk_tier = TIER_HIGH
    elif score >= 20:
        risk_tier = TIER_MEDIUM
    else:
        risk_tier = TIER_LOW

    # ── Recommended action ────────────────────────────────────────────────────
    actions = {
        TIER_CRITICAL: "Immediate review — disable pending investigation",
        TIER_HIGH:     "Review within 5 business days — raise SNOW CR",
        TIER_MEDIUM:   "Schedule review — owner to confirm justification",
        TIER_LOW:      "No immediate action — include in next quarterly review",
    }

    return {
        **sp,
        "highest_privilege":  highest_privilege,
        "findings":           findings,
        "score":              min(score, 100),
        "risk_tier":          risk_tier,
        "recommended_action": actions[risk_tier],
        "finding_count":      len(findings),
    }


def run_classification(data_path: str) -> list[dict]:
    """
    Load all principals and return fully classified results.
    Groups by login to get unique role mappings per login
    before classifying.
    """
    raw = load_principals(data_path)

    # ── Group role mappings by login ──────────────────────────────────────────
    login_map = {}
    for row in raw:
        key = (
            row["principal_name"],
            row["sql_instance"]
        )
        if key not in login_map:
            login_map[key] = {
                **row,
                "role_mappings": []
            }
        role = row.get("role_mapping", "LOW_PRIVILEGE")
        if role not in login_map[key]["role_mappings"]:
            login_map[key]["role_mappings"].append(role)

    # ── Classify each unique login ────────────────────────────────────────────
    return [classify_principal(sp) for sp in login_map.values()]