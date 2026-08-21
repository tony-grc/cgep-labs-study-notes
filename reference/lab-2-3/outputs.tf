# outputs.tf - Lab 2.3

output "bucket_name" {
  value       = aws_s3_bucket.primary.bucket
  description = "Primary bucket name."
}

output "bucket_arn" {
  value       = aws_s3_bucket.primary.arn
  description = "Primary bucket ARN."
}

output "log_bucket_name" {
  value       = aws_s3_bucket.log.bucket
  description = "Access-log bucket name."
}

output "log_bucket_arn" {
  value       = aws_s3_bucket.log.arn
  description = "Access-log bucket ARN."
}

output "kms_key_arn" {
  value       = aws_kms_key.bucket.arn
  description = "CMK protecting both buckets (SC-12 / SC-13 attestation)."
}

# The attestation is this module's evidence surface. Lab 2.4 builds the same
# shape on GCP; Lab 6.1's OSCAL component points at the JSON it lands in.
#
# The one() expressions are deliberate. Terraform models these blocks as
# SETS, which are not index-addressable. tolist(...)[0] would work and is
# worse: it silently returns an arbitrary element if there were ever two.
# one() raises instead. This output is an attestation, so failing loudly
# beats attesting confidently to the wrong value.
output "compliance_attestation" {
  description = "Computed attestation of the controls this primitive enforces."
  value = {
    encryption_algorithm = one([
      for rule in aws_s3_bucket_server_side_encryption_configuration.primary.rule :
      rule.apply_server_side_encryption_by_default[0].sse_algorithm
    ])
    kms_key_arn          = aws_kms_key.bucket.arn
    kms_rotation_enabled = aws_kms_key.bucket.enable_key_rotation
    primary_versioning   = aws_s3_bucket_versioning.primary.versioning_configuration[0].status
    log_versioning       = aws_s3_bucket_versioning.log.versioning_configuration[0].status
    public_access_blocked = alltrue([
      aws_s3_bucket_public_access_block.primary.block_public_acls,
      aws_s3_bucket_public_access_block.primary.block_public_policy,
      aws_s3_bucket_public_access_block.primary.ignore_public_acls,
      aws_s3_bucket_public_access_block.primary.restrict_public_buckets,
    ])
    acls_disabled = one([
      for rule in aws_s3_bucket_ownership_controls.primary.rule : rule.object_ownership
    ]) == "BucketOwnerEnforced"
    tls_required          = true
    access_logging_target = aws_s3_bucket_logging.primary.target_bucket
    log_retention_days    = var.log_retention_days
  }
}
