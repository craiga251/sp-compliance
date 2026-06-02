variable "project_id" {
  description = "GCP project ID"
  type        = string
  default     = "sp-compliance"
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west2"
}

variable "bq_dataset_id" {
  description = "BigQuery dataset ID"
  type        = string
  default     = "sp_compliance"
}

variable "bq_location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "EU"
}