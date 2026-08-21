# Mixed-compliance fixture for Lab 3.3.
# Compliant and non-compliant GCS buckets plus a firewall rule, so the
# policy suite has something concrete to flag. Plan-only; never applied.

terraform {
  required_version = ">= 1.9"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

variable "gcp_project" {
  type = string
}

locals {
  labels = {
    project          = "lab33"
    environment      = "dev"
    managed_by       = "terraform"
    compliance_scope = "cge-p-lab"
  }
}

resource "google_kms_key_ring" "ring" {
  name     = "lab33-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "key" {
  name     = "lab33-key"
  key_ring = google_kms_key_ring.ring.id
}

# A compliant log bucket: versioned, so AU-9 is satisfiable.
resource "google_storage_bucket" "logs" {
  name                        = "${var.gcp_project}-lab33-logs"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = local.labels
}

# An UNVERSIONED log bucket. AU-9 should fire on anything logging here.
resource "google_storage_bucket" "bad_logs" {
  name                        = "${var.gcp_project}-lab33-badlogs"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = local.labels
}

# Fully compliant.
resource "google_storage_bucket" "good" {
  name                        = "${var.gcp_project}-lab33-good"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  logging {
    log_bucket        = google_storage_bucket.logs.name
    log_object_prefix = "access-logs/"
  }

  labels = local.labels
}

# SC-28 should fire: no encryption block.
resource "google_storage_bucket" "bad_no_cmek" {
  name                        = "${var.gcp_project}-lab33-no-cmek"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  logging {
    log_bucket = google_storage_bucket.logs.name
  }

  labels = local.labels
}

# AC-3 should fire: uniform access off, prevention not enforced.
resource "google_storage_bucket" "bad_public" {
  name                        = "${var.gcp_project}-lab33-public"
  location                    = "us-central1"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }

  labels = local.labels
}

# CM-6 should fire: no labels.
resource "google_storage_bucket" "bad_no_labels" {
  name                        = "${var.gcp_project}-lab33-no-labels"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  logging {
    log_bucket = google_storage_bucket.logs.name
  }
}

# AU-3 should fire: no logging block at all.
resource "google_storage_bucket" "bad_no_logging" {
  name                        = "${var.gcp_project}-lab33-no-logging"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  labels = local.labels
}

# AU-9 should fire: logs to a bucket that is not versioned.
resource "google_storage_bucket" "bad_log_target" {
  name                        = "${var.gcp_project}-lab33-badtarget"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.key.id
  }

  logging {
    log_bucket = google_storage_bucket.bad_logs.name
  }

  labels = local.labels
}

resource "google_compute_network" "demo" {
  name                    = "lab33-demo"
  auto_create_subnetworks = false
}

# AC-3 should fire.
resource "google_compute_firewall" "open_ssh" {
  name          = "lab33-open-ssh"
  network       = google_compute_network.demo.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
