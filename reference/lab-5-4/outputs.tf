output "workload_identity_provider" {
  value       = "projects/${var.gcp_project}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/providers/${google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id}"
  description = "Paste into google-github-actions/auth as workload_identity_provider."
}

output "service_account_email" {
  value       = google_service_account.gha.email
  description = "Paste into google-github-actions/auth as service_account."
}

output "enforce_mode" {
  value       = var.enforce_mode
  description = "dry_run or enforce. Org Policy attestation."
}
