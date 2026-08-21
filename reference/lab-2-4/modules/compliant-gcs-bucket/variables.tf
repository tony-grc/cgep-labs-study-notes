# variables.tf - Lab 2.4 module interface
# Rule: expose only what the business changes. Everything compliance-relevant
# is hardcoded in main.tf where consumers cannot reach it.

variable "gcp_project" {
  type        = string
  description = "GCP project ID where the bucket and KMS resources live."
}

variable "location" {
  type        = string
  description = "GCS bucket location. Multi-regions like US and EU are valid."
  default     = "us-central1"
}

# Two location variables because GCS accepts multi-regions and KMS does not.
# Setting both from one variable fails with KMS_RESOURCE_NOT_FOUND_IN_LOCATION
# the first time you try "US".
variable "kms_location" {
  type        = string
  description = "KMS keyring location. Must be a single region."
  default     = "us-central1"
}

variable "project_label" {
  type        = string
  description = "Short project identifier."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_label))
    error_message = "project_label must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment."
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "retention_days" {
  type        = number
  description = "Minimum object retention in days. Production must be >= 365."

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 3650
    error_message = "retention_days must be between 1 and 3650."
  }

  # Cross-variable validation, needs Terraform >= 1.9. This is the preventive
  # control the lab's negative test demonstrates.
  validation {
    condition     = var.environment != "prod" || var.retention_days >= 365
    error_message = "retention_days must be >= 365 when environment == \"prod\"."
  }
}

variable "log_retention_days" {
  type        = number
  description = "AU-11. Age at which access-log objects are deleted."
  default     = 90
}

variable "keep_noncurrent_versions" {
  type        = number
  description = "How many superseded versions to retain before lifecycle deletes them."
  default     = 3
}

variable "lock_retention_policy" {
  type        = bool
  description = "IRREVERSIBLE. Locking a retention policy prevents shortening or removing it, and the bucket cannot be deleted until every object ages out."
  default     = false
}

variable "bucket_name_suffix" {
  type        = string
  description = "Globally-unique suffix appended to the bucket name."
  validation {
    condition     = can(regex("^[a-z0-9-]{3,30}$", var.bucket_name_suffix))
    error_message = "bucket_name_suffix must be 3-30 lowercase alphanumerics or hyphens."
  }
}

variable "labels" {
  type        = map(string)
  description = "Optional additional labels. Required compliance labels merge on top."
  default     = {}
}
