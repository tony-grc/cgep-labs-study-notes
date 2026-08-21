# outputs.tf - Lab 5.2

output "trail_arn" {
  value       = aws_cloudtrail.mgmt.arn
  description = "Feed to `aws cloudtrail validate-logs --trail-arn` for the AU-9 check."
}

output "trail_bucket" {
  value       = aws_s3_bucket.trail.id
  description = "Bucket holding trail logs. Also the Athena LOCATION prefix."
}

output "trail_kms_key_arn" {
  value       = aws_kms_key.trail.arn
  description = "CMK protecting the trail."
}

output "athena_workgroup" {
  value       = aws_athena_workgroup.grc.name
  description = "Workgroup for the AU-6 review queries in queries/."
}

output "glue_database" {
  value       = aws_glue_catalog_database.trail.name
  description = "Database the cloudtrail_logs external table belongs in."
}

output "athena_table_location" {
  value       = "s3://${aws_s3_bucket.trail.id}/AWSLogs/${local.account_id}/CloudTrail/"
  description = "Paste into the CREATE EXTERNAL TABLE LOCATION clause."
}
