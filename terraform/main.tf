# SP Compliance Platform - GCP Infrastructure
# Provisions BigQuery, Cloud Storage, Artifact Registry and Cloud Run
# Region: europe-west2 (London) - keeps data in UK

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5.0"
}

# ── Provider ──────────────────────────────────────────────────────────────────
provider "google" {
  project = var.project_id
  region  = var.region
}

# ── Enable required APIs ──────────────────────────────────────────────────────
resource "google_project_service" "bigquery" {
  service            = "bigquery.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "storage" {
  service            = "storage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloudrun" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifactregistry" {
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

# ── Cloud Storage bucket — raw data landing zone ──────────────────────────────
resource "google_storage_bucket" "sp_compliance_raw" {
  name          = "${var.project_id}-raw-data"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# ── BigQuery dataset ──────────────────────────────────────────────────────────
resource "google_bigquery_dataset" "sp_compliance" {
  dataset_id  = var.bq_dataset_id
  location    = var.bq_location
  description = "SP Compliance Platform dataset"

  depends_on = [google_project_service.bigquery]
}

# ── BigQuery table: principals ────────────────────────────────────────────────
resource "google_bigquery_table" "principals" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "principals"
  deletion_protection = false
  description         = "Core SP inventory - one row per login per role mapping"

  schema = jsonencode([
    { name = "principal_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "principal_name",     type = "STRING",    mode = "REQUIRED" },
    { name = "principal_type",     type = "STRING",    mode = "NULLABLE" },
    { name = "sql_instance",       type = "STRING",    mode = "NULLABLE" },
    { name = "login_enabled",      type = "STRING",    mode = "NULLABLE" },
    { name = "interactive",        type = "STRING",    mode = "NULLABLE" },
    { name = "privilege_summary",  type = "STRING",    mode = "NULLABLE" },
    { name = "created_date",       type = "STRING",    mode = "NULLABLE" },
    { name = "scan_run_id",        type = "STRING",    mode = "NULLABLE" }
  ])
}

# ── BigQuery table: permissions ───────────────────────────────────────────────
resource "google_bigquery_table" "permissions" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "permissions"
  deletion_protection = false
  description         = "Native SQL permissions - one row per permission per login"

  schema = jsonencode([
    { name = "permission_id",      type = "STRING",    mode = "REQUIRED" },
    { name = "scan_run_id",        type = "STRING",    mode = "REQUIRED" },
    { name = "principal_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "principal_name",     type = "STRING",    mode = "NULLABLE" },
    { name = "sql_instance",       type = "STRING",    mode = "NULLABLE" },
    { name = "database_name",      type = "STRING",    mode = "NULLABLE" },
    { name = "native_permission",  type = "STRING",    mode = "NULLABLE" },
    { name = "role_mapping",       type = "STRING",    mode = "NULLABLE" },
    { name = "created_at",         type = "TIMESTAMP", mode = "NULLABLE" }
  ])
}

# ── BigQuery table: classifications ──────────────────────────────────────────
resource "google_bigquery_table" "classifications" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "classifications"
  deletion_protection = false
  description         = "Risk tier and score per SP per scan run"

  schema = jsonencode([
    { name = "classification_id",  type = "STRING",    mode = "REQUIRED" },
    { name = "scan_run_id",        type = "STRING",    mode = "REQUIRED" },
    { name = "principal_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "principal_name",     type = "STRING",    mode = "NULLABLE" },
    { name = "risk_tier",          type = "STRING",    mode = "NULLABLE" },
    { name = "score",              type = "INTEGER",   mode = "NULLABLE" },
    { name = "finding_count",      type = "INTEGER",   mode = "NULLABLE" },
    { name = "recommended_action", type = "STRING",    mode = "NULLABLE" },
    { name = "classified_at",      type = "TIMESTAMP", mode = "NULLABLE" }
  ])
}

# ── BigQuery table: findings ──────────────────────────────────────────────────
resource "google_bigquery_table" "findings" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "findings"
  deletion_protection = false
  description         = "Individual control failures per SP per scan run"

  schema = jsonencode([
    { name = "finding_id",         type = "STRING",    mode = "REQUIRED" },
    { name = "scan_run_id",        type = "STRING",    mode = "REQUIRED" },
    { name = "principal_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "principal_name",     type = "STRING",    mode = "NULLABLE" },
    { name = "finding_text",       type = "STRING",    mode = "NULLABLE" },
    { name = "risk_tier",          type = "STRING",    mode = "NULLABLE" },
    { name = "created_at",         type = "TIMESTAMP", mode = "NULLABLE" }
  ])
}

# ── BigQuery table: remediation_packs ─────────────────────────────────────────
resource "google_bigquery_table" "remediation_packs" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "remediation_packs"
  deletion_protection = false
  description         = "Generated remediation actions per SP"

  schema = jsonencode([
    { name = "pack_id",            type = "STRING",    mode = "REQUIRED" },
    { name = "principal_id",       type = "STRING",    mode = "REQUIRED" },
    { name = "principal_name",     type = "STRING",    mode = "NULLABLE" },
    { name = "risk_tier",          type = "STRING",    mode = "NULLABLE" },
    { name = "action_summary",     type = "STRING",    mode = "NULLABLE" },
    { name = "snow_cr_template",   type = "STRING",    mode = "NULLABLE" },
    { name = "generated_at",       type = "TIMESTAMP", mode = "NULLABLE" }
  ])
}

# ── BigQuery table: scan_runs ─────────────────────────────────────────────────
resource "google_bigquery_table" "scan_runs" {
  dataset_id          = google_bigquery_dataset.sp_compliance.dataset_id
  table_id            = "scan_runs"
  deletion_protection = false
  description         = "Audit trail of every classification scan"

  schema = jsonencode([
    { name = "scan_run_id",        type = "STRING",    mode = "REQUIRED" },
    { name = "started_at",         type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "completed_at",       type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "total_principals",   type = "INTEGER",   mode = "NULLABLE" },
    { name = "critical_count",     type = "INTEGER",   mode = "NULLABLE" },
    { name = "high_count",         type = "INTEGER",   mode = "NULLABLE" },
    { name = "medium_count",       type = "INTEGER",   mode = "NULLABLE" },
    { name = "low_count",          type = "INTEGER",   mode = "NULLABLE" },
    { name = "source",             type = "STRING",    mode = "NULLABLE" }
  ])
}

# ── Artifact Registry — stores container images ───────────────────────────────
resource "google_artifact_registry_repository" "sp_compliance" {
  location      = var.region
  repository_id = "sp-compliance"
  format        = "DOCKER"
  description   = "SP Compliance Portal container images"

  depends_on = [google_project_service.artifactregistry]
}

# ── Service account for Cloud Run ─────────────────────────────────────────────
resource "google_service_account" "cloudrun_sa" {
  account_id   = "sp-compliance-cloudrun"
  display_name = "SP Compliance Cloud Run Service Account"
}

# ── Grant Cloud Run SA access to BigQuery ─────────────────────────────────────
resource "google_project_iam_member" "cloudrun_bq_reader" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.cloudrun_sa.email}"
}

resource "google_project_iam_member" "cloudrun_bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.cloudrun_sa.email}"
}

# ── Cloud Run service ─────────────────────────────────────────────────────────
resource "google_cloud_run_v2_service" "sp_compliance_portal" {
  name     = "sp-compliance-portal"
  location = var.region

  template {
    service_account = google_service_account.cloudrun_sa.email

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/sp-compliance/portal:latest"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [
    google_project_service.cloudrun,
    google_artifact_registry_repository.sp_compliance,
  ]
}

# ── Allow public access to Cloud Run portal ───────────────────────────────────
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.sp_compliance_portal.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}