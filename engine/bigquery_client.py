# BigQuery Data Client
# Handles all data reads and writes from BigQuery
# All queries filter by latest scan_run_id
# ensuring portal always shows most recent scan

from google.cloud import bigquery
from datetime import datetime, timezone
import uuid
import pandas as pd

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ID = "sp-compliance"
DATASET_ID = "sp_compliance"

# ── BigQuery client ───────────────────────────────────────────────────────────
def get_client() -> bigquery.Client:
    """Return authenticated BigQuery client."""
    return bigquery.Client(project=PROJECT_ID)

def query_to_df(sql: str) -> pd.DataFrame:
    """Run a BigQuery SQL query and return results as a DataFrame."""
    client = get_client()
    return client.query(sql).to_dataframe()

def bq_str(value: str) -> str:
    """
    Escape a string value for safe use in BigQuery SQL.
    Handles backslashes in SQL Server instance names
    e.g. SQLPROD01\MSSQLPROD
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")

def get_latest_scan_run_id() -> str:
    """
    Fetch the most recent scan_run_id.
    All queries filter by this to show latest scan only.
    """
    sql = f"""
        SELECT scan_run_id
        FROM `{PROJECT_ID}.{DATASET_ID}.scan_runs`
        ORDER BY started_at DESC
        LIMIT 1
    """
    df = query_to_df(sql)
    if df.empty:
        return ""
    return str(df.iloc[0]["scan_run_id"])

# ── LEVEL 1 — Server summary ──────────────────────────────────────────────────

def get_server_summary() -> pd.DataFrame:
    """
    Fetch one row per server instance showing headline risk.
    Filtered to latest scan run only.
    """
    scan_run_id = get_latest_scan_run_id()
    if not scan_run_id:
        return pd.DataFrame()

    sql = f"""
        SELECT
            p.sql_instance,
            MAX(c.risk_tier)                        AS highest_risk_tier,
            MAX(c.score)                            AS highest_score,
            COUNT(DISTINCT c.principal_id)          AS login_count,
            SUM(c.finding_count)                    AS total_findings,
            COUNTIF(c.risk_tier = 'CRITICAL')       AS critical_logins,
            COUNTIF(c.risk_tier = 'HIGH')           AS high_logins,
            COUNTIF(c.risk_tier = 'MEDIUM')         AS medium_logins,
            COUNTIF(c.risk_tier = 'LOW')            AS low_logins
        FROM
            `{PROJECT_ID}.{DATASET_ID}.classifications` c
        LEFT JOIN (
            SELECT
                principal_id,
                MAX(sql_instance) AS sql_instance
            FROM `{PROJECT_ID}.{DATASET_ID}.principals`
            WHERE scan_run_id = '{scan_run_id}'
            GROUP BY principal_id
        ) p ON c.principal_id = p.principal_id
        WHERE c.scan_run_id = '{scan_run_id}'
        GROUP BY p.sql_instance
        ORDER BY highest_score DESC
    """
    return query_to_df(sql)


# ── LEVEL 2 — Permissions grid per server ─────────────────────────────────────

def get_permissions_for_instance(sql_instance: str) -> pd.DataFrame:
    """
    Fetch one row per login per native permission for a server instance.
    Filtered to latest scan run only.
    """
    scan_run_id   = get_latest_scan_run_id()
    safe_instance = bq_str(sql_instance)

    sql = f"""
        SELECT
            perm.principal_id,
            perm.principal_name,
            perm.native_permission,
            perm.role_mapping,
            perm.database_name,
            perm.sql_instance,
            c.risk_tier,
            c.score,
            p.login_enabled,
            p.interactive,
            p.principal_type
        FROM
            `{PROJECT_ID}.{DATASET_ID}.permissions` perm
        LEFT JOIN
            `{PROJECT_ID}.{DATASET_ID}.classifications` c
            ON perm.principal_id = c.principal_id
            AND c.scan_run_id = '{scan_run_id}'
        LEFT JOIN (
            SELECT principal_id,
                   MAX(login_enabled)  AS login_enabled,
                   MAX(interactive)    AS interactive,
                   MAX(principal_type) AS principal_type
            FROM `{PROJECT_ID}.{DATASET_ID}.principals`
            WHERE scan_run_id = '{scan_run_id}'
            GROUP BY principal_id
        ) p ON perm.principal_id = p.principal_id
        WHERE perm.sql_instance  = '{safe_instance}'
        AND   perm.scan_run_id   = '{scan_run_id}'
        AND   perm.native_permission IS NOT NULL
        AND   perm.native_permission != ''
        ORDER BY c.score DESC, perm.principal_name, perm.native_permission
    """
    return query_to_df(sql)


# ── LEVEL 3 — Findings and permissions for drilldown ─────────────────────────

def get_classifications() -> pd.DataFrame:
    """
    Fetch all classifications joined with principal details.
    Filtered to latest scan run only.
    """
    scan_run_id = get_latest_scan_run_id()

    sql = f"""
        SELECT
            c.principal_id,
            c.principal_name,
            c.risk_tier,
            c.score,
            c.finding_count,
            c.recommended_action,
            c.classified_at,
            p.principal_type,
            p.sql_instance,
            p.login_enabled,
            p.interactive,
            p.privilege_summary
        FROM
            `{PROJECT_ID}.{DATASET_ID}.classifications` c
        LEFT JOIN (
            SELECT
                principal_id,
                MAX(principal_type)    AS principal_type,
                MAX(sql_instance)      AS sql_instance,
                MAX(login_enabled)     AS login_enabled,
                MAX(interactive)       AS interactive,
                STRING_AGG(DISTINCT privilege_summary, ', '
                    ORDER BY privilege_summary) AS privilege_summary
            FROM `{PROJECT_ID}.{DATASET_ID}.principals`
            WHERE scan_run_id = '{scan_run_id}'
            GROUP BY principal_id
        ) p ON c.principal_id = p.principal_id
        WHERE c.scan_run_id = '{scan_run_id}'
        ORDER BY c.score DESC
    """
    return query_to_df(sql)


def get_findings_for_principal(principal_id: str) -> pd.DataFrame:
    """Fetch all findings for a specific principal from latest scan."""
    scan_run_id = get_latest_scan_run_id()
    safe_id     = bq_str(principal_id)

    sql = f"""
        SELECT
            finding_id,
            finding_text,
            risk_tier,
            created_at
        FROM `{PROJECT_ID}.{DATASET_ID}.findings`
        WHERE principal_id = '{safe_id}'
        AND   scan_run_id  = '{scan_run_id}'
        ORDER BY created_at DESC
    """
    return query_to_df(sql)


def get_permissions_for_principal(principal_id: str) -> pd.DataFrame:
    """Fetch all native permissions for a specific principal from latest scan."""
    scan_run_id = get_latest_scan_run_id()
    safe_id     = bq_str(principal_id)

    sql = f"""
        SELECT
            sql_instance,
            database_name,
            native_permission,
            role_mapping
        FROM `{PROJECT_ID}.{DATASET_ID}.permissions`
        WHERE principal_id = '{safe_id}'
        AND   scan_run_id  = '{scan_run_id}'
        ORDER BY role_mapping, native_permission
    """
    return query_to_df(sql)


def get_permissions_grouped(principal_id: str) -> dict:
    """
    Fetch native permissions grouped by role mapping.
    Filtered to latest scan run.
    """
    scan_run_id = get_latest_scan_run_id()
    safe_id     = bq_str(principal_id)

    sql = f"""
        SELECT
            role_mapping,
            native_permission,
            sql_instance,
            database_name
        FROM `{PROJECT_ID}.{DATASET_ID}.permissions`
        WHERE principal_id = '{safe_id}'
        AND   scan_run_id  = '{scan_run_id}'
        AND   native_permission IS NOT NULL
        AND   native_permission != ''
        ORDER BY role_mapping, native_permission
    """
    df = query_to_df(sql)
    if df.empty:
        return {}

    grouped = {}
    for _, row in df.iterrows():
        role     = str(row["role_mapping"])
        perm     = str(row["native_permission"])
        instance = str(row["sql_instance"])
        db       = str(row["database_name"])

        if role not in grouped:
            grouped[role] = []

        grouped[role].append({
            "native_permission": perm,
            "sql_instance":      instance,
            "database_name":     db,
        })

    return grouped


def get_scan_summary() -> dict:
    """Fetch the latest scan run summary for the metrics row."""
    sql = f"""
        SELECT
            total_principals,
            critical_count,
            high_count,
            medium_count,
            low_count,
            started_at
        FROM `{PROJECT_ID}.{DATASET_ID}.scan_runs`
        ORDER BY started_at DESC
        LIMIT 1
    """
    df = query_to_df(sql)
    if df.empty:
        return {}
    return df.iloc[0].to_dict()


# ── Finding actions — read ────────────────────────────────────────────────────

def get_actions_for_permission(
    principal_id:      str,
    native_permission: str,
    database_name:     str
) -> pd.DataFrame:
    """
    Fetch all actions recorded for a specific permission on a principal.
    """
    safe_id   = bq_str(principal_id)
    safe_perm = bq_str(native_permission)
    safe_db   = bq_str(database_name)

    sql = f"""
        SELECT
            action_id,
            action_type,
            status,
            environment,
            snow_cr_number,
            risk_ref,
            notes,
            actioned_by,
            actioned_at,
            review_date
        FROM `{PROJECT_ID}.{DATASET_ID}.finding_actions`
        WHERE principal_id      = '{safe_id}'
        AND   native_permission = '{safe_perm}'
        AND   database_name     = '{safe_db}'
        ORDER BY actioned_at DESC
    """
    return query_to_df(sql)


# ── Finding actions — write ───────────────────────────────────────────────────

def save_remediation_action(
    finding_id:        str,
    principal_id:      str,
    principal_name:    str,
    native_permission: str,
    database_name:     str,
    sql_instance:      str,
    environment:       str,
    snow_cr_number:    str,
    notes:             str,
    actioned_by:       str = "Portal User",
) -> bool:
    """Save a remediation action to finding_actions table."""
    client = get_client()
    row = [{
        "action_id":          str(uuid.uuid4()),
        "finding_id":         finding_id,
        "principal_id":       principal_id,
        "principal_name":     principal_name,
        "native_permission":  native_permission,
        "database_name":      database_name,
        "sql_instance":       sql_instance,
        "action_type":        "REMEDIATE",
        "status":             f"{environment}_RAISED",
        "environment":        environment,
        "snow_cr_number":     snow_cr_number,
        "risk_ref":           "",
        "notes":              notes,
        "actioned_by":        actioned_by,
        "actioned_at":        datetime.now(timezone.utc).isoformat(),
        "review_date":        "",
    }]
    errors = client.insert_rows_json(
        f"{PROJECT_ID}.{DATASET_ID}.finding_actions", row
    )
    return len(errors) == 0


def save_risk_acceptance(
    finding_id:        str,
    principal_id:      str,
    principal_name:    str,
    native_permission: str,
    database_name:     str,
    sql_instance:      str,
    risk_ref:          str,
    review_date:       str,
    notes:             str,
    actioned_by:       str = "Portal User",
) -> bool:
    """Save a risk acceptance to finding_actions table."""
    client = get_client()
    row = [{
        "action_id":          str(uuid.uuid4()),
        "finding_id":         finding_id,
        "principal_id":       principal_id,
        "principal_name":     principal_name,
        "native_permission":  native_permission,
        "database_name":      database_name,
        "sql_instance":       sql_instance,
        "action_type":        "RISK_ACCEPTED",
        "status":             "RISK_ACCEPTED",
        "environment":        "",
        "snow_cr_number":     "",
        "risk_ref":           risk_ref,
        "notes":              notes,
        "actioned_by":        actioned_by,
        "actioned_at":        datetime.now(timezone.utc).isoformat(),
        "review_date":        review_date,
    }]
    errors = client.insert_rows_json(
        f"{PROJECT_ID}.{DATASET_ID}.finding_actions", row
    )
    return len(errors) == 0