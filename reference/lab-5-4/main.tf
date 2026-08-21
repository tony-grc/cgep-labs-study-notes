# main.tf - Lab 5.4: GCP Security Services Baseline
# Controls: CM-6, AC-2, AC-3, IA-5, AU-2, AU-3, AU-12
# SC-8 is INHERITED: the Google APIs are TLS-only.
# SC-7 (VPC Service Controls) is deliberately NOT built; see README.

terraform {
  required_version = ">= 1.9"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

# ---------------------------------------------------------------------------
# Org Policy: rejection AT THE API, not a finding afterward.
#
# enforce_mode = "dry_run" observes without blocking. Roll out that way
# first, watch the violations, then promote to "enforce".
#
# Do NOT try to audit by omitting the rules block. A policy with no rules is
# not auditing, it is NOT IN EFFECT: you would observe zero violations and
# conclude you were compliant. dry_run_spec is the mechanism that audits.
# ---------------------------------------------------------------------------
locals {
  constraints = {
    uniform_bucket_access    = "storage.uniformBucketLevelAccess" # CM-6
    public_access_prevention = "storage.publicAccessPrevention"   # AC-3
    disable_sa_keys          = "iam.disableServiceAccountKeyCreation"
    require_oslogin          = "compute.requireOsLogin" # AC-3
  }
}

resource "google_org_policy_policy" "constraints" {
  for_each = local.constraints

  name   = "projects/${var.gcp_project}/policies/${each.value}"
  parent = "projects/${var.gcp_project}"

  dynamic "spec" {
    for_each = var.enforce_mode == "enforce" ? [1] : []
    content {
      rules {
        enforce = "TRUE"
      }
    }
  }

  dynamic "dry_run_spec" {
    for_each = var.enforce_mode == "dry_run" ? [1] : []
    content {
      rules {
        enforce = "TRUE"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# IA-5 / AC-2: Workload Identity Federation replaces service account keys.
#
# Two layers of defense here, and students routinely build only one:
#   attribute_condition on the PROVIDER decides who may exchange a token.
#   principalSet in the BINDING decides who may impersonate this account.
# Set only the first and a mistake in it is unsurvivable.
# ---------------------------------------------------------------------------
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
  }

  # AC-3. Without this line the provider trusts ALL of GitHub: any repository
  # on the public internet could present a token and impersonate the account.
  attribute_condition = "assertion.repository == \"${var.github_org}/${var.github_repo}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "gha" {
  account_id   = "cgep-grc-gate-sa"
  display_name = "CGE-P GRC gate (read-only)"
}

# AC-6: the gate plans and inspects; it does not change anything.
resource "google_project_iam_member" "gha_viewer" {
  project = var.gcp_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.gha.email}"
}

resource "google_service_account_iam_binding" "wif_user" {
  service_account_id = google_service_account.gha.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_org}/${var.github_repo}",
  ]
}

# ---------------------------------------------------------------------------
# AU-2 / AU-3 / AU-12: Data Access logs. OFF BY DEFAULT, and the single
# most-cited GCP audit finding because nobody turns them on.
#
# Turning them on is AU-2 and AU-12. READING them is AU-6, same caution as
# Lab 5.2: a log nobody reviews is a cost center, not a control.
# ---------------------------------------------------------------------------
resource "google_project_iam_audit_config" "services" {
  for_each = toset(var.data_access_log_services)

  project = var.gcp_project
  service = each.value

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
