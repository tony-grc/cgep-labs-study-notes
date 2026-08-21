# outputs.tf - Lab 2.2

output "state_bucket" {
  value       = aws_s3_bucket.tfstate.id
  description = "Bucket name. Paste into every other workspace's backend block."
}

output "state_kms_key_arn" {
  value       = aws_kms_key.tfstate.arn
  description = "CMK ARN protecting state at rest."
}

output "backend_block" {
  description = "Copy-paste backend configuration for every other lab."
  value       = <<-EOT
    backend "s3" {
      bucket       = "${aws_s3_bucket.tfstate.id}"
      key          = "CHANGE-ME/terraform.tfstate"
      region       = "${var.aws_region}"
      encrypt      = true
      kms_key_id   = "${aws_kms_key.tfstate.arn}"
      use_lockfile = true
    }
  EOT
}
