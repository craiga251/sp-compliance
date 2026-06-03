# Remediation Pack Generator
# Generates pre-populated ServiceNow CR templates per principal
# Shows both role mapping and native permission layers
# IAM team sees role mappings — app team confirms native permissions

from datetime import datetime, timezone
import uuid
import json

# ── Remediation templates per finding type ────────────────────────────────────
REMEDIATION_TEMPLATES = {
    "Critical privilege assigned: SYSADMIN": {
        "action":    "Remove SYSADMIN role and replace with least privilege role",
        "urgency":   "1 - High",
        "risk":      "Unauthorised full server access",
        "test_plan": "Verify application/service still functions after role change",
        "backout":   "Restore SYSADMIN role if application impact confirmed",
    },
    "Critical privilege assigned: SQL SERVER ADMIN": {
        "action":    "Remove SQL SERVER ADMIN role and replace with least privilege",
        "urgency":   "1 - High",
        "risk":      "Unauthorised server administration access",
        "test_plan": "Verify application/service still functions after role change",
        "backout":   "Restore SQL SERVER ADMIN role if application impact confirmed",
    },
    "Critical privilege assigned: SECURITYADMIN": {
        "action":    "Remove SECURITYADMIN role — reassign only if justified",
        "urgency":   "1 - High",
        "risk":      "Account can grant any permission including SYSADMIN",
        "test_plan": "Verify no legitimate security management dependency",
        "backout":   "Restore SECURITYADMIN if business justification confirmed",
    },
    "Elevated privilege assigned: DB_OWNER": {
        "action":    "Replace DB_OWNER with db_datareader/db_datawriter as appropriate",
        "urgency":   "2 - Medium",
        "risk":      "Full database control including schema changes",
        "test_plan": "Verify application functions with reduced privilege",
        "backout":   "Restore DB_OWNER if application impact confirmed",
    },
    "Elevated privilege assigned: DATABASE ADMIN": {
        "action":    "Review DDL requirements — replace with db_ddladmin if justified",
        "urgency":   "2 - Medium",
        "risk":      "Unrestricted schema modification capability",
        "test_plan": "Verify application functions with reduced privilege",
        "backout":   "Restore DATABASE ADMIN if application impact confirmed",
    },
    "Login is disabled but account still exists": {
        "action":    "Remove disabled account from SQL Server instance",
        "urgency":   "2 - Medium",
        "risk":      "Disabled account could be re-enabled and misused",
        "test_plan": "Confirm no application dependency before removal",
        "backout":   "Recreate account with original permissions if needed",
    },
    "Non-interactive account holds elevated privilege": {
        "action":    "Review service account privilege — apply least privilege",
        "urgency":   "2 - Medium",
        "risk":      "Service account with elevated privilege increases attack surface",
        "test_plan": "Verify service continues to function with reduced privilege",
        "backout":   "Restore original privilege if service impact confirmed",
    },
    "Windows Group assigned elevated privilege — membership not directly auditable": {
        "action":    "Review AD group membership — confirm all members require this privilege",
        "urgency":   "2 - Medium",
        "risk":      "Group membership may include users who do not require this privilege",
        "test_plan": "Confirm group membership with AD team before changes",
        "backout":   "No SQL Server change required — AD group membership change only",
    },
    "Dev/test account name detected on production instance": {
        "action":    "Remove dev/test account from production instance immediately",
        "urgency":   "1 - High",
        "risk":      "Dev/test accounts should never exist in production",
        "test_plan": "Confirm no production dependency before removal",
        "backout":   "Recreate account only if genuine production dependency confirmed",
    },
    "Multiple elevated privileges assigned": {
        "action":    "Review all role mappings — remove all but the minimum required",
        "urgency":   "2 - Medium",
        "risk":      "Excessive privilege accumulation increases breach impact",
        "test_plan": "Test application with each privilege removed individually",
        "backout":   "Restore individual privileges if specific dependency confirmed",
    },
}

# ── Default template for unmatched findings ───────────────────────────────────
DEFAULT_TEMPLATE = {
    "action":    "Review finding with application owner and IAM team",
    "urgency":   "3 - Low",
    "risk":      "Compliance gap identified — manual review required",
    "test_plan": "Confirm with application owner before any changes",
    "backout":   "No change made — review only",
}


def get_template(finding_text: str) -> dict:
    """
    Match a finding to a remediation template.
    Uses prefix matching to handle dynamic finding text.
    """
    for key, template in REMEDIATION_TEMPLATES.items():
        if finding_text.startswith(key[:40]):
            return template
    return DEFAULT_TEMPLATE


def generate_remediation_pack(
    classified_sp: dict,
    permissions_grouped: dict = None
) -> dict:
    """
    Generate a remediation pack for a single classified principal.

    Parameters:
        classified_sp:       classified principal dict from classifier
        permissions_grouped: dict of { role_mapping: [permissions] }
                             from get_permissions_grouped()
                             Shows native permissions under each role mapping

    Returns a dict containing:
        - pack_id
        - principal details
        - risk tier and score
        - action_summary
        - permission_breakdown: role mappings with native permissions
        - snow_cr_template: pre-populated SNOW CR as JSON string
        - steps: individual remediation steps per finding
    """
    findings            = classified_sp.get("findings", [])
    risk_tier           = classified_sp.get("risk_tier", "LOW")
    score               = classified_sp.get("score", 0)
    permissions_grouped = permissions_grouped or {}

    # ── Build remediation steps ───────────────────────────────────────────────
    steps = []
    for finding in findings:
        template = get_template(finding)
        steps.append({
            "finding":   finding,
            "action":    template["action"],
            "urgency":   template["urgency"],
            "risk":      template["risk"],
            "test_plan": template["test_plan"],
            "backout":   template["backout"],
        })

    # ── Build permission breakdown ────────────────────────────────────────────
    # Shows IAM team the role mappings
    # Shows app team the native permissions underneath each role mapping
    permission_breakdown = []
    for role_mapping, perms in permissions_grouped.items():
        permission_breakdown.append({
            "role_mapping":       role_mapping,
            "native_permissions": perms,
            "permission_count":   len(perms),
            "iam_action":         (
                f"Review whether {role_mapping} is required "
                f"— {len(perms)} native permission(s) underneath"
            ),
            "app_team_action":    (
                f"Confirm which of the {len(perms)} permission(s) "
                f"under {role_mapping} are required for application function"
            ),
        })

    # ── Build action summary ──────────────────────────────────────────────────
    if steps:
        highest_urgency = min(steps, key=lambda x: x["urgency"])
        action_summary  = (
            f"{len(steps)} remediation action(s) required. "
            f"Highest urgency: {highest_urgency['urgency']}. "
            f"Recommended: {highest_urgency['action']}"
        )
    else:
        action_summary = "No remediation required — principal is compliant"

    # ── Build permission detail for SNOW CR ───────────────────────────────────
    permission_detail = ""
    for pb in permission_breakdown:
        permission_detail += f"\n  Role Mapping: {pb['role_mapping']}\n"
        for p in pb["native_permissions"]:
            permission_detail += (
                f"    - {p['native_permission']}"
                f" ({p['database_name']} on {p['sql_instance']})\n"
            )

    # ── Build SNOW CR template ────────────────────────────────────────────────
    snow_cr = {
        "short_description": (
            f"IAM Compliance Remediation — "
            f"{classified_sp.get('principal_name', '')} — "
            f"{risk_tier}"
        ),
        "description": (
            f"Principal:  {classified_sp.get('principal_name', '')}\n"
            f"Instance:   {classified_sp.get('sql_instance', '')}\n"
            f"Risk Tier:  {risk_tier}\n"
            f"Score:      {score}\n\n"
            f"Findings:\n" +
            "\n".join(f"  - {f}" for f in findings) +
            f"\n\nRemediation Steps:\n" +
            "\n".join(
                f"  {i+1}. {s['action']}"
                for i, s in enumerate(steps)
            ) +
            f"\n\nPermission Breakdown (IAM + App Team):{permission_detail}"
        ),
        "category":         "Security",
        "subcategory":      "Access Management",
        "urgency":          steps[0]["urgency"] if steps else "3 - Low",
        "impact":           "2 - Medium" if risk_tier in ["HIGH", "CRITICAL"] else "3 - Low",
        "assignment_group": "IAM Security Team",
        "requested_by":     "SP Compliance Platform",
        "justification":    (
            f"Automated finding from SP Compliance scan "
            f"— Risk Score: {score}"
        ),
        "test_plan":        steps[0]["test_plan"] if steps else "No changes required",
        "backout_plan":     steps[0]["backout"]   if steps else "No changes required",
        "generated_at":     datetime.now(timezone.utc).isoformat(),
    }

    return {
        "pack_id":              str(uuid.uuid4()),
        "principal_id":         classified_sp.get("principal_id", ""),
        "principal_name":       classified_sp.get("principal_name", ""),
        "risk_tier":            risk_tier,
        "score":                score,
        "action_summary":       action_summary,
        "permission_breakdown": permission_breakdown,
        "snow_cr_template":     json.dumps(snow_cr, indent=2),
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "steps":                steps,
    }


def generate_all_packs(classified_principals: list[dict]) -> list[dict]:
    """Generate remediation packs for all classified principals."""
    return [
        generate_remediation_pack(sp)
        for sp in classified_principals
        if sp.get("findings")
    ]