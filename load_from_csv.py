# CSV ACL Loader
# Loads real ACL extract CSV into BigQuery
# Handles the exact column format from MSSQL_ACL_v1_01.sql output
# Replaces load_to_bigquery.py for production use

import uuid
import sys
import pandas as pd
from datetime import datetime, timezone
from pathlib import Path
from google.cloud import bigquery

# Add engine to path
sys.path.append(str(Path(__file__).parent))
from engine.classifier import classify_principal, get_highest_privilege

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ID  = "sp-compliance"
DATASET_ID  = "sp_compliance"

# ── Column name mapping ───────────────────────────────────────────────────────
# Maps ACL script output columns to our internal field names
# Handles typos in the CSV headers (Privlege, Date Creted)
COLUMN_MAP = {
    "SQL Server Name":  "sql_instance",
    "Login Type":       "principal_type",
    "Login Name":       "principal_name",
    "Enabled":          "login_enabled",
    "Interactive":      "interactive",
    "Database Name ":   "database_name",   # trailing space in header
    "Database Name":    "database_name",   # without trailing space
    "Privlege":         "native_permission", # typo in ACL script
    "Privilege":        "native_permission", # correct spelling
    "Role Mapping":     "role_mapping",
    "Date Creted ":     "created_date",    # typo in ACL script
    "Date Created":     "created_date",    # correct spelling
}

# ── BigQuery client ───────────────────────────────────────────────────────────
client = bigquery.Client(project=PROJECT_ID)

def full_table_id(table_name: str) -> str:
    return f"{PROJECT_ID}.{DATASET_ID}.{table_name}"

def load_table(table_id: str, rows: list[dict]) -> None:
    if not rows:
        print(f"⚠️  No rows to load into {table_id} — skipping")
        return
    errors = client.insert_rows_json(table_id, rows)
    if errors:
        print(f"❌ Errors loading {table_id}: {errors}")
    else:
        print(f"✅ Loaded {len(rows)} rows into {table_id}")

def load_csv(filepath: str) -> None:
    """
    Load an ACL extract CSV into BigQuery.
    Handles column name variations and typos from the ACL script.
    """
    path = Path(filepath)
    if not path.exists():
        print(f"❌ File not found: {filepath}")
        sys.exit(1)

    print(f"\n📂 Loading file: {filepath}")

    # ── Read CSV ──────────────────────────────────────────────────────────────
    df = pd.read_csv(filepath)

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Rename columns using mapping
    df = df.rename(columns=COLUMN_MAP)

    print(f"📊 Rows in CSV: {len(df)}")
    print(f"📋 Columns: {list(df.columns)}")

    # ── Validate required columns exist ───────────────────────────────────────
    required = [
        "sql_instance", "principal_type", "principal_name",
        "login_enabled", "interactive", "role_mapping"
    ]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"❌ Missing required columns: {missing}")
        sys.exit(1)

    # ── Generate scan run ID ──────────────────────────────────────────────────
    scan_run_id = str(uuid.uuid4())
    scanned_at  = datetime.now(timezone.utc).isoformat()

    print(f"\n🔍 Scan run ID: {scan_run_id}")
    print(f"📅 Timestamp:   {scanned_at}\n")

    # ── Build permissions rows ────────────────────────────────────────────────
    # One row per native permission per login per database
    permissions_rows = []
    for _, row in df.iterrows():
        permissions_rows.append({
            "permission_id":     str(uuid.uuid4()),
            "scan_run_id":       scan_run_id,
            "principal_id":      str(uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"{row['principal_name']}_{row['sql_instance']}"
            )),
            "principal_name":    str(row.get("principal_name", "")),
            "sql_instance":      str(row.get("sql_instance", "")),
            "database_name":     str(row.get("database_name", "")),
            "native_permission": str(row.get("native_permission", "")),
            "role_mapping":      str(row.get("role_mapping", "")),
            "created_at":        scanned_at,
        })

    # ── Group by login to get unique role mappings ────────────────────────────
    login_map = {}
    for _, row in df.iterrows():
        principal_name = str(row["principal_name"])
        sql_instance   = str(row["sql_instance"])
        key            = f"{principal_name}_{sql_instance}"
        principal_id   = str(uuid.uuid5(uuid.NAMESPACE_DNS, key))

        if key not in login_map:
            login_map[key] = {
                "principal_id":   principal_id,
                "principal_name": principal_name,
                "principal_type": str(row.get("principal_type", "")),
                "sql_instance":   sql_instance,
                "login_enabled":  str(row.get("login_enabled", "YES")),
                "interactive":    str(row.get("interactive",    "YES")),
                "created_date":   str(row.get("created_date",   "")),
                "role_mappings":  [],
            }

        role = str(row.get("role_mapping", "LOW_PRIVILEGE")).strip()
        if role and role not in login_map[key]["role_mappings"]:
            login_map[key]["role_mappings"].append(role)

    # ── Classify each unique login ────────────────────────────────────────────
    classified = []
    for sp in login_map.values():
        result = classify_principal(sp)
        classified.append(result)

    # ── Build principals rows ─────────────────────────────────────────────────
    principals_rows = []
    seen = set()
    for sp in classified:
        for role in sp["role_mappings"]:
            key = (sp["principal_name"], sp["sql_instance"], role)
            if key not in seen:
                seen.add(key)
                principals_rows.append({
                    "principal_id":      sp["principal_id"],
                    "principal_name":    sp["principal_name"],
                    "principal_type":    sp.get("principal_type", ""),
                    "sql_instance":      sp.get("sql_instance", ""),
                    "login_enabled":     sp.get("login_enabled", "YES"),
                    "interactive":       sp.get("interactive",   "YES"),
                    "privilege_summary": role,
                    "created_date":      sp.get("created_date",  ""),
                    "scan_run_id":       scan_run_id,
                })

    # ── Build classifications rows ────────────────────────────────────────────
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
        "source":           str(path.name),
    }]

    # ── Load all tables ───────────────────────────────────────────────────────
    load_table(full_table_id("principals"),      principals_rows)
    load_table(full_table_id("permissions"),     permissions_rows)
    load_table(full_table_id("classifications"), classification_rows)
    load_table(full_table_id("findings"),        findings_rows)
    load_table(full_table_id("scan_runs"),       scan_run_row)

    print(f"\n🎉 Load complete")
    print(f"   File:          {path.name}")
    print(f"   Total logins:  {len(classified)}")
    print(f"   Critical:      {scan_run_row[0]['critical_count']}")
    print(f"   High:          {scan_run_row[0]['high_count']}")
    print(f"   Medium:        {scan_run_row[0]['medium_count']}")
    print(f"   Low:           {scan_run_row[0]['low_count']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python load_from_csv.py <path_to_csv>")
        print("Example: python load_from_csv.py data\\sample.csv")
        sys.exit(1)
    load_csv(sys.argv[1])