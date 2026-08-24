# main.tf - Lab 2.4: Terraform Modules for Compliance (GCP)
# Controls: SC-12, SC-13, SC-28, AC-3, AU-3, AU-9, AU-11, CM-6, CM-8
# SC-8 is INHERITED from GCP: the Cloud Storage API is TLS-only, so there
# is no module-level control to write. Lab 6.1 records that honestly as an
# OSCAL implementation-status of "inherited" rather than "implemented".

terraform {
  required_version = ">= 1.9"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # No provider block. Consumers configure it; this module inherits it.
  # A module carrying its own provider cannot be reused across regions or
  # accounts, which is the structural mistake Lab 2.3 makes on purpose.
}

locals {
  # CM-6 / CM-8: merged ON TOP of consumer labels. That asymmetry is what
  # makes them non-negotiable: a consumer may add labels, never suppress.
  required_labels = {
    project          = var.project_label
    environment      = var.environment
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }

  effective_labels = merge(var.labels, local.required_labels)

  # GCS bucket names sit in ONE namespace shared by every Google customer, so
  # a fixed name is a name a stranger may already hold. Lab 2.3 met the same
  # wall on S3 and answers it the same way: generate a suffix, allow an
  # override when a name has to be predictable.
  effective_suffix = coalesce(var.bucket_suffix, random_id.bucket_suffix.hex)

  bucket_name = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}-${local.effective_suffix}"
  log_name    = "${var.project_label}-${var.environment}-${var.bucket_name_suffix}-logs-${local.effective_suffix}"

  # KMS names are scoped to this project and location, not to Google, so they
  # need no random suffix and deliberately do not carry one. A key ring cannot
  # be deleted from a project, so a name that churns on every apply leaves an
  # orphan behind permanently.
  keyring_id = "${var.environment}-${var.bucket_name_suffix}-ring"
  key_id     = "${var.environment}-${var.bucket_name_suffix}-key"
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

data "google_storage_project_service_account" "gcs" {
  project = var.gcp_project
}

# SC-12: cryptographic key establishment and management. We own the key.
resource "google_kms_key_ring" "ring" {
  name     = local.keyring_id
  location = var.kms_location
  project  = var.gcp_project
}

# SC-12 / SC-13: 90-day rotation, expressed in seconds because the API is
# not sorry about it. 7776000 = 90 * 24 * 60 * 60.
resource "google_kms_crypto_key" "key" {
  name            = local.key_id
  key_ring        = google_kms_key_ring.ring.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = false # set true in production
  }
}

resource "google_kms_crypto_key_iam_member" "gcs_encrypter" {
  crypto_key_id = google_kms_crypto_key.key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

# ---------------------------------------------------------------------------
# AU-3 / AU-9: the access-log bucket. Logs belong somewhere other than the
# thing they are logging.
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "log" {
  name     = local.log_name
  project  = var.gcp_project
  location = var.location

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # AU-9: audit records must survive overwrite.
  versioning {
    enabled = true
  }

  # AU-11: logs expire on a schedule instead of accumulating forever.
  lifecycle_rule {
    condition {
      age = var.log_retention_days
    }
    action {
      type = "Delete"
    }
  }

  labels = local.effective_labels
}

# GCS writes access logs as the Cloud Storage Analytics group. This is the
# GCP analogue of the AWS log-delivery bucket-policy grant in Lab 2.3.
resource "google_storage_bucket_iam_member" "log_writer" {
  bucket = google_storage_bucket.log.name
  role   = "roles/storage.objectCreator"
  member = "group:cloud-storage-analytics@google.com"
}

# ---------------------------------------------------------------------------
# The primary bucket. AC-3 + SC-28 + AU-3 + AU-11 + CM-6 in one declaration.
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "bucket" {
  name     = local.bucket_name
  project  = var.gcp_project
  location = var.location

  # AC-3: uniform access removes per-object ACLs entirely (the GCP
  # equivalent of BucketOwnerEnforced); public_access_prevention refuses
  # public grants even if someone with IAM rights tries to add one.
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # SC-13 / SC-28: CMEK. Without this block GCS still encrypts at rest with
  # a Google-managed key, which is encryption you cannot rotate or audit.
  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  # AU-11, mechanism one: retention_policy is WORM. Objects cannot be
  # deleted until they reach this age. A floor.
  retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = var.lock_retention_policy
  }

  # AU-11, mechanism two: lifecycle expires superseded versions. A ceiling.
  # Versioning without this is an unbounded bill.
  lifecycle_rule {
    condition {
      num_newer_versions = var.keep_noncurrent_versions
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  # AU-3: access logs to the dedicated bucket.
  logging {
    log_bucket        = google_storage_bucket.log.name
    log_object_prefix = "access-logs/"
  }

  labels = local.effective_labels

  # Genuine dependency: the GCS service account must hold encrypt/decrypt on
  # the key BEFORE the bucket is created, and nothing here references the
  # IAM binding for Terraform to infer it from.
  depends_on = [google_kms_crypto_key_iam_member.gcs_encrypter]
}
