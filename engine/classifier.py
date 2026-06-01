# SP Compliance Classification Engine
# Loads SP data from JSON, applies risk rules, returns classified results
# Each rule is explicit and auditable - no black box decisions

import json
from pathlib import Path

# ── Risk tiers ────────────────────────────────────────────────────────────────
TIER_CRITICAL = "CRITICAL"
TIER_HIGH     = "HIGH"
TIER_MEDIUM   = "MEDIUM"
TIER_LOW      = "LOW"

# ── Roles considered high privilege ───────────────────────────────────────────
HIGH_PRIVILEGE_ROLES = ["sysadmin", "db_owner", "securityadmin"]

# ── Dormant threshold in days ─────────────────────────────────────────────────
DORMANT_DAYS = 90


def load_principals(filepath: str) -> list[dict]:
    """Load raw SP records from a JSON file."""
    path = Path(filepath)
    with open(path, "r") as f:
        return json.load(f)


def classify_principal(sp: dict) -> dict:
    """
    Apply compliance rules to a single SP record.
    Returns the original record plus:
      - findings: list of specific control failures
      - score:    integer 0-100 (higher = more risk)
      - risk_tier: CRITICAL / HIGH / MEDIUM / LOW
      - recommended_action: plain English next step
    """
    findings = []
    score = 0

    # ── RULE 1: Excessive privilege ───────────────────────────────────────────
    if sp["sql_role"] in HIGH_PRIVILEGE_ROLES:
        findings.append(f"Excessive privilege: {sp['sql_role']} role assigned")
        score += 30

    # ── RULE 2: Direct connect ────────────────────────────────────────────────
    if sp["direct_connect"]:
        findings.append("Direct connect: bypasses connection controls")
        score += 25

    # ── RULE 3: No application owner ─────────────────────────────────────────
    if not sp["has_application_owner"]:
        findings.append("No application owner recorded")
        score += 20

    # ── RULE 4: No justification on file ─────────────────────────────────────
    if not sp["justification_on_file"]:
        findings.append("No justification on file")
        score += 10

    # ── RULE 5: Dormant account ───────────────────────────────────────────────
    if sp["last_used_days_ago"] > DORMANT_DAYS:
        findings.append(
            f"Dormant: not used in {sp['last_used_days_ago']} days"
        )
        score += 20

    # ── RULE 6: Dev account in production ────────────────────────────────────
    if (sp["environment"] == "Production" and
            any(kw in sp["principal_name"].lower()
                for kw in ["dev", "test", "uat", "staging"])):
        findings.append("Dev/test account exists in Production environment")
        score += 30

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
        "findings":             findings,
        "score":                min(score, 100),
        "risk_tier":            risk_tier,
        "recommended_action":   actions[risk_tier],
        "finding_count":        len(findings),
    }


def run_classification(data_path: str) -> list[dict]:
    """Load all principals and return fully classified results."""
    principals = load_principals(data_path)
    return [classify_principal(sp) for sp in principals]