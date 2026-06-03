# BigQuery Data Client
# Handles all data reads from BigQuery
# Replaces local JSON file reads in the portal
# Falls back to local JSON if BigQuery is unavailable

from google.cloud import bigquery
from google.api_core.exceptions import GoogleAPIError
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

# ── Data fetch functions ──────────────────────────────────────────────────────

def get_classifications() -> pd.DataFrame:
    """
    Fetch all classifications joined with principal details.
    Returns one row per login with risk tier and score.
    """
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
            GROUP BY principal_id
        ) p ON c.principal_id = p.principal_id
        ORDER BY c.score DESC
    """
    return query_to_df(sql)


def get_findings_for_principal(principal_id: str) -> pd.DataFrame:
    """
    Fetch all findings for a specific principal.
    Used in the drilldown view.
    """
    sql = f"""
        SELECT
            finding_text,
            risk_tier,
            created_at
        FROM `{PROJECT_ID}.{DATASET_ID}.findings`
        WHERE principal_id = '{principal_id}'
        ORDER BY created_at DESC
    """
    return query_to_df(sql)


def get_permissions_for_principal(principal_id: str) -> pd.DataFrame:
    """
    Fetch all native permissions for a specific principal.
    Used in the drilldown view for IAM team.
    """
    sql = f"""
        SELECT
            sql_instance,
            database_name,
            native_permission,
            role_mapping
        FROM `{PROJECT_ID}.{DATASET_ID}.permissions`
        WHERE principal_id = '{principal_id}'
        ORDER BY role_mapping, native_permission
    """
    return query_to_df(sql)


def get_scan_summary() -> dict:
    """
    Fetch the latest scan run summary.
    Used for the metrics row at the top of the portal.
    """
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