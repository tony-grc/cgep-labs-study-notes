output "role_arn" {
  value       = aws_iam_role.grc_gate.arn
  description = "Set this as the AWS_ROLE_ARN repository variable."
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.github.arn
  description = "Import this if the provider already exists in the account."
}
