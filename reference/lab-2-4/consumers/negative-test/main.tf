# consumers/negative-test/main.tf - Lab 2.4
# DELIBERATELY INVALID: prod with 30-day retention.
# 'terraform plan' must FAIL at variable validation, before any API call.

terraform {
  required_version = ">= 1.9"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

# The provider lives HERE, in the root module, not in the module. That is the
# structural lesson of this lab.
provider "google" {
  project = var.gcp_project
  region  = "us-central1"
}

variable "gcp_project" {
  type = string
}

module "data_bucket" {
  source = "../../modules/compliant-gcs-bucket"

  gcp_project        = var.gcp_project
  project_label      = "cgep-lab"
  environment        = "prod"
  retention_days     = 30
  bucket_name_suffix = "should-never-exist"
}

output "attestation" {
  value = module.data_bucket.compliance_attestation
}

output "bucket_url" {
  value = module.data_bucket.bucket_url
}
