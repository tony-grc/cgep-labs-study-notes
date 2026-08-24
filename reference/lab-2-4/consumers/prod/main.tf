# consumers/prod/main.tf - Lab 2.4
# Same module, two values changed.

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
  retention_days     = 365
  bucket_name_suffix = "data-001"
}

# Named compliance_attestation, matching Lab 2.3 and the module itself. The
# name is load-bearing: Lab 2.5's evidence bundler runs
# `terraform output -json compliance_attestation` against whatever workspace
# it is pointed at, and swallows a miss with `|| true`. A consumer that calls
# this something else produces an empty bundle and no error.
output "compliance_attestation" {
  value = module.data_bucket.compliance_attestation
}

output "bucket_url" {
  value = module.data_bucket.bucket_url
}

# The verification steps read these rather than pasting a literal name, which
# they cannot do now that the suffix is generated.
output "bucket_name" {
  value = module.data_bucket.bucket_name
}

output "log_bucket_name" {
  value = module.data_bucket.log_bucket_name
}
