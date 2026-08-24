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

# A handle to the key this module made, for consumers that need to reference
# it. It is plumbing, not evidence: it says a key exists, not that the bucket
# uses it. The attestation below reads that from the bucket.
output "kms_key_id" {
  value       = google_kms_crypto_key.key.id
  description = "Resource ID of the CMEK this module created."
}

# Same evidence surface as Lab 2.3's compliance_attestation, different cloud.
# That similarity is what lets one Rego library and one OSCAL component
# describe both.
output "compliance_attestation" {
  description = "Computed attestation of the controls this module enforces."
  value = {
    # Read back from the resource, never from the variable that set it. An
    # attestation that repeats its own input cannot be wrong, which means it
    # cannot be right either: delete the encryption block and a hardcoded
    # "cmek" still says cmek. Same reasoning as Lab 2.3's one() on the S3 side,
    # and the null it returns on absence is the loud failure we want.
    encryption_type          = length(google_storage_bucket.bucket.encryption) > 0 ? "cmek" : "google-managed"
    kms_key_id               = one([for e in google_storage_bucket.bucket.encryption : e.default_kms_key_name])
    kms_rotation_period      = google_kms_crypto_key.key.rotation_period
    versioning_enabled       = google_storage_bucket.bucket.versioning[0].enabled
    log_versioning_enabled   = google_storage_bucket.log.versioning[0].enabled
    public_access_prevention = google_storage_bucket.bucket.public_access_prevention
    uniform_access_enforced  = google_storage_bucket.bucket.uniform_bucket_level_access
    access_logging_target    = google_storage_bucket.bucket.logging[0].log_bucket
    # is_locked is the sharp case for reading the resource rather than the
    # input. Locking is a one-way API call that can be made from the console or
    # gcloud without Terraform, so var.lock_retention_policy would attest false
    # on a bucket that is genuinely, permanently locked.
    retention_period_days   = one([for r in google_storage_bucket.bucket.retention_policy : r.retention_period / 86400])
    retention_policy_locked = one([for r in google_storage_bucket.bucket.retention_policy : r.is_locked])

    log_retention_days = one([
      for r in google_storage_bucket.log.lifecycle_rule : r.condition[0].age
      if r.action[0].type == "Delete"
    ])

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
