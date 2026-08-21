# outputs.tf - Lab 2.5

output "vault_name" {
  value       = aws_s3_bucket.vault.id
  description = "Vault bucket name. Feed to capture-evidence.sh --vault."
}

output "vault_kms_key_arn" {
  value       = aws_kms_key.vault.arn
  description = "CMK protecting the vault."
}

output "lock_mode" {
  value       = var.lock_mode
  description = "Retention mode in force (AU-11 attestation)."
}

output "retention_days" {
  value       = var.retention_days
  description = "Default retention window in days (AU-11 attestation)."
}
