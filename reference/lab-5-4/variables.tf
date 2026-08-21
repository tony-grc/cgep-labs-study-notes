variable "gcp_project" {
  type        = string
  description = "GCP project ID."
}

variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "github_org" {
  type        = string
  description = "GitHub organization or user. Bound into the WIF attribute_condition."
}

variable "github_repo" {
  type        = string
  description = "Repository name. The provider trusts only this repo."
}

variable "enforce_mode" {
  type        = string
  description = "dry_run observes and logs violations without blocking; enforce rejects at the API. Roll out dry_run first."
  default     = "dry_run"
  validation {
    condition     = contains(["dry_run", "enforce"], var.enforce_mode)
    error_message = "enforce_mode must be dry_run or enforce."
  }
}

variable "data_access_log_services" {
  type        = list(string)
  description = "Services to enable Data Access logs for. These bill at $0.50/GB ingested; start with storage alone in a busy project."
  default     = ["storage.googleapis.com", "cloudkms.googleapis.com", "iam.googleapis.com"]
}
