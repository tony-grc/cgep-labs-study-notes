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
  validation {
    # An EMPTY string is the dangerous case, not a missing one. Terraform stops
    # on a variable that was never set; it accepts "" and builds from it, and
    # the OIDC sub condition becomes "repo:/your-repo:*", which no real token
    # can match. The role is then un-assumable and the failure surfaces in CI
    # as "invalid identity token", which sends you looking at the wrong thing.
    condition     = length(var.github_org) > 0
    error_message = "github_org must not be empty. Set TF_VAR_github_org in cgep.env."
  }
}

variable "github_repo" {
  type        = string
  description = "Repository name. The provider trusts only this repo."
  validation {
    # An EMPTY string is the dangerous case, not a missing one. Terraform stops
    # on a variable that was never set; it accepts "" and builds from it, and
    # the OIDC sub condition becomes "repo:/your-repo:*", which no real token
    # can match. The role is then un-assumable and the failure surfaces in CI
    # as "invalid identity token", which sends you looking at the wrong thing.
    condition     = length(var.github_repo) > 0
    error_message = "github_repo must not be empty. Set TF_VAR_github_repo in cgep.env."
  }
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
