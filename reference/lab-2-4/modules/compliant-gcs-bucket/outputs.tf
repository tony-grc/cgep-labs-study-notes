# outputs.tf - Lab 2.4

output "bucket_url" {
  value       = google_storage_bucket.bucket.url
  description = "gs:// URL of the compliant bucket."
}

output "bucket_name" {
  value       = google_storage_bucket.bucket.name
  description = "Name of the compliant bucket."
}

output "log_bucket_name" {
  value       = google_storage_bucket.log.name
  description = "Name of the access-log bucket."
}

output "kms_key_id" {
  value       = google_kms_crypto_key.key.id
  description = "Resource ID of the CMEK protecting this bucket."
}

# Same evidence surface as Lab 2.3's compliance_attestation, different cloud.
# That similarity is what lets one Rego library and one OSCAL component
# describe both.
output "compliance_attestation" {
  description = "Computed attestation of the controls this module enforces."
  value = {
    encryption_type          = "cmek"
    kms_key_id               = google_kms_crypto_key.key.id
    kms_rotation_period      = google_kms_crypto_key.key.rotation_period
    versioning_enabled       = google_storage_bucket.bucket.versioning[0].enabled
    log_versioning_enabled   = google_storage_bucket.log.versioning[0].enabled
    public_access_prevention = google_storage_bucket.bucket.public_access_prevention
    uniform_access_enforced  = google_storage_bucket.bucket.uniform_bucket_level_access
    access_logging_target    = google_storage_bucket.bucket.logging[0].log_bucket
    retention_period_days    = var.retention_days
    retention_policy_locked  = var.lock_retention_policy
    log_retention_days       = var.log_retention_days

    required_labels_present = alltrue([
      for k in keys(local.required_labels) :
      contains(keys(google_storage_bucket.bucket.labels), k)
    ])

    # SC-8 is satisfied by the platform, not by this module. Saying so here
    # is the honest form; Lab 6.1 maps it to implementation-status
    # "inherited" with GCP named as the responsible party.
    transit_encryption = "inherited-gcp-tls-only"
  }
}
