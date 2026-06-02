# BigQuery Data Loader
# Loads ACL extract data into BigQuery
# Populates: principals, classifications, findings, scan_runs tables
# Source: data/principals.json (prototype) — real source is ACL CSV extract

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from google.cloud import bigquery
from engine.classifier import run_classification, load_principals

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ID  = "sp-compliance"
DATASET_ID  = "sp_compliance"
DATA_PATH   = "data/principals.json"

# ── BigQuery client ───────────────────────────────────────────────────────────
client = bigquery.Client(project=PROJECT_ID)

def full_table_id(table_name: str) -> str:
    """Return fully qualified BigQuery table ID."""
    return f"{PROJECT_ID}.{DATASET_ID}.{table_name}"

def load_table(table_id: str, rows: list[dict]) -> None:
    """Insert rows into a BigQuery table and report result."""
    errors = client.insert_rows_json(table_id, rows)
    if errors:
        print(f"❌ Errors loading {table_id}: {errors}")
    else:
        print(f"✅ Loaded {len(rows)} rows into {table_id}")

def main():
    # ── Generate a unique scan run ID ─────────────────────────────────────────
    scan_run_id = str(uuid.uuid4())
    scanned_at  = datetime.now(timezone.utc).isoformat()

    print(f"\n🔍 Starting scan run: {scan_run_id}")
    print(f"📅 Timestamp: {scanned_at}\n")

    # ── Load raw data and run classification ──────────────────────────────────
    raw_rows   = load_principals(DATA_PATH)
    classified = run_classification(DATA_PATH)

    # ── Build principals rows ─────────────────────────────────────────────────
    # One row per login per unique role mapping
    principal_rows = []
    seen = set()

    for sp in classified:
        for role in sp["role_mappings"]:
            key = (sp["principal_name"], sp["sql_instance"], role)
            if key not in seen:
                seen.add(key)
                principal_rows.append({
                    "principal_id":      sp["principal_id"],
                    "principal_name":    sp["principal_name"],
                    "principal_type":    sp.get("principal_type", ""),
                    "sql_instance":      sp.get("sql_instance", ""),
                    "login_enabled":     sp.get("login_enabled", "YES"),
                    "interactive":       sp.get("interactive", "YES"),
                    "privilege_summary": role,
                    "created_date":      sp.get("created_date", ""),
                    "scan_run_id":       scan_run_id,
                })

    # ── Build permissions rows ────────────────────────────────────────────────
    # One row per native permission per login per database
    # In prototype this mirrors raw rows
    # In production this comes from the full ACL extract
    permissions_rows = []
    for row in raw_rows:
        permissions_rows.append({
            "permission_id":     str(uuid.uuid4()),
            "scan_run_id":       scan_run_id,
            "principal_id":      row["principal_id"],
            "principal_name":    row["principal_name"],
            "sql_instance":      row.get("sql_instance", ""),
            "database_name":     row.get("database_name", ""),
            "native_permission": row.get("native_permission", ""),
            "role_mapping":      row.get("role_mapping", ""),
            "created_at":        scanned_at,
        })

    # ── Build classifications rows ────────────────────────────────────────────
    # One row per login — risk score based on highest privilege
    classification_rows = [
        {
            "classification_id":  str(uuid.uuid4()),
            "scan_run_id":        scan_run_id,
            "principal_id":       sp["principal_id"],
            "principal_name":     sp["principal_name"],
            "risk_tier":          sp["risk_tier"],
            "score":              sp["score"],
            "finding_count":      sp["finding_count"],
            "recommended_action": sp["recommended_action"],
            "classified_at":      scanned_at,
        }
        for sp in classified
    ]

    # ── Build findings rows ───────────────────────────────────────────────────
    # One row per finding per login
    findings_rows = [
        {
            "finding_id":     str(uuid.uuid4()),
            "scan_run_id":    scan_run_id,
            "principal_id":   sp["principal_id"],
            "principal_name": sp["principal_name"],
            "finding_text":   finding,
            "risk_tier":      sp["risk_tier"],
            "created_at":     scanned_at,
        }
        for sp in classified
        for finding in sp["findings"]
    ]

    # ── Build scan_runs row ───────────────────────────────────────────────────
    scan_run_row = [{
        "scan_run_id":      scan_run_id,
        "started_at":       scanned_at,
        "completed_at":     datetime.now(timezone.utc).isoformat(),
        "total_principals": len(classified),
        "critical_count":   sum(1 for s in classified if s["risk_tier"] == "CRITICAL"),
        "high_count":       sum(1 for s in classified if s["risk_tier"] == "HIGH"),
        "medium_count":     sum(1 for s in classified if s["risk_tier"] == "MEDIUM"),
        "low_count":        sum(1 for s in classified if s["risk_tier"] == "LOW"),
        "source":           "local_json",
    }]

    # ── Load all tables ───────────────────────────────────────────────────────
    load_table(full_table_id("principals"),      principal_rows)
    load_table(full_table_id("permissions"),     permissions_rows)
    load_table(full_table_id("classifications"), classification_rows)
    load_table(full_table_id("findings"),        findings_rows)
    load_table(full_table_id("scan_runs"),       scan_run_row)

    print(f"\n🎉 Scan run complete")
    print(f"   Total logins:  {len(classified)}")
    print(f"   Critical:      {scan_run_row[0]['critical_count']}")
    print(f"   High:          {scan_run_row[0]['high_count']}")
    print(f"   Medium:        {scan_run_row[0]['medium_count']}")
    print(f"   Low:           {scan_run_row[0]['low_count']}")

if __name__ == "__main__":
    main()