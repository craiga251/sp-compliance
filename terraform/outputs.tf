output "bigquery_dataset_id" {
  description = "BigQuery dataset ID"
  value       = google_bigquery_dataset.sp_compliance.dataset_id
}

output "bigquery_dataset_location" {
  description = "BigQuery dataset location"
  value       = google_bigquery_dataset.sp_compliance.location
}

output "storage_bucket_name" {
  description = "Cloud Storage bucket name"
  value       = google_storage_bucket.sp_compliance_raw.name
}

output "storage_bucket_url" {
  description = "Cloud Storage bucket URL"
  value       = google_storage_bucket.sp_compliance_raw.url
}

output "principals_table" {
  description = "BigQuery principals table ID"
  value       = google_bigquery_table.principals.table_id
}

output "permissions_table" {
  description = "BigQuery permissions table ID"
  value       = google_bigquery_table.permissions.table_id
}

output "artifact_registry_url" {
  description = "Artifact Registry URL for container images"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/sp-compliance"
}

output "cloud_run_url" {
  description = "Cloud Run portal URL"
  value       = google_cloud_run_v2_service.sp_compliance_portal.uri
}