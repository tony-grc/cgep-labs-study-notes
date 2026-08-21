# main.tf - Lab 2.3: First Compliant Resource (AWS S3)
# Controls implemented: SC-8, SC-8(1), SC-12, SC-13, SC-28, SC-28(1),
#                       AC-3, AC-6, AU-3, AU-9, AU-11, CM-6, CM-8, CP-9, SI-7
#
# AU-6 is deliberately NOT claimed here. AU-6 is audit review and analysis;
# nothing in this workspace reads the logs. Lab 5.2 earns it with Athena.

terraform {
  required_version = ">= 1.10"

  # Partial backend configuration. The account-specific values live in
  # backend.hcl, which is gitignored, so a real bucket name and key ARN
  # never land in a public repository:
  #
  #   cp backend.hcl.example backend.hcl   # then fill in your values
  #   terraform init -backend-config=backend.hcl
  #
  # Omit -backend-config and Terraform prompts for the missing values, so
  # the workspace still runs without the file.
  backend "s3" {
    key          = "labs/2-3/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region

  # CM-6 / CM-8: required compliance tags on every taggable resource.
  # CM-6 is the configuration-settings argument; CM-8 is the stronger one,
  # because ComplianceScope is how you enumerate an authorization boundary
  # with an API call instead of a spreadsheet.
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = var.environment
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  effective_suffix = coalesce(var.bucket_suffix, random_id.bucket_suffix.hex)
  primary_name     = "${var.project_name}-${var.environment}-data-${local.effective_suffix}"
  log_name         = "${var.project_name}-${var.environment}-logs-${local.effective_suffix}"
}

# ---------------------------------------------------------------------------
# SC-12 (key management) + SC-13 (cryptographic protection)
# A customer-managed key with rotation. This is what an AWS-managed key
# cannot give you: rotation policy you set and a key policy you can read.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "bucket" {
  description             = "CMK for ${local.primary_name} and its access-log bucket"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "bucket" {
  name          = "alias/${var.project_name}-${var.environment}-s3"
  target_key_id = aws_kms_key.bucket.key_id
}

data "aws_iam_policy_document" "kms" {
  # Omitting this statement makes the key permanently unmanageable.
  statement {
    sid       = "EnableAccountRootAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # S3 server access log delivery encrypts each log object with this key.
  # SourceAccount is confused-deputy protection: it stops another account
  # inducing the S3 logging service to use your key on their behalf.
  statement {
    sid       = "AllowS3LogDelivery"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# ---------------------------------------------------------------------------
# Buckets
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "primary" {
  bucket = local.primary_name
}

resource "aws_s3_bucket" "log" {
  bucket = local.log_name
}

# AC-6: ACLs disabled entirely. The tempting alternative, BucketOwnerPreferred
# plus a log-delivery-write ACL, re-enables ACLs and trips Security Hub control
# S3.12. Log delivery is granted by bucket policy below instead.
resource "aws_s3_bucket_ownership_controls" "primary" {
  bucket = aws_s3_bucket.primary.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_ownership_controls" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SC-28: encryption at rest with the CMK, not the AWS-managed default.
resource "aws_s3_bucket_server_side_encryption_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucket.arn
    }
    bucket_key_enabled = true
  }
}

# bucket_key_enabled is REQUIRED here, not merely economical: an SSE-KMS
# server-access-log destination bucket must have S3 Bucket Keys on.
resource "aws_s3_bucket_server_side_encryption_configuration" "log" {
  bucket = aws_s3_bucket.log.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucket.arn
    }
    bucket_key_enabled = true
  }
}

# CP-9 / SI-7: prior object states survive deletion and overwrite.
resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AU-9: protection of audit information. Easy to omit, and the omission is
# quiet: without it, log objects can be overwritten in place, leaving the
# bucket holding your audit records less protected than the one holding data.
resource "aws_s3_bucket_versioning" "log" {
  bucket = aws_s3_bucket.log.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: all four flags. Three is not enough.
resource "aws_s3_bucket_public_access_block" "primary" {
  bucket                  = aws_s3_bucket.primary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "log" {
  bucket                  = aws_s3_bucket.log.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-11: audit record retention, and the difference between a lab and an
# unbounded S3 invoice.
resource "aws_s3_bucket_lifecycle_configuration" "log" {
  bucket     = aws_s3_bucket.log.id
  depends_on = [aws_s3_bucket_versioning.log]

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    # Empty filter = all objects. Provider 5.x rejects a rule with neither
    # filter nor prefix.
    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Note what this rule does NOT do: expire current object versions. Expiring
# live data is a business decision, not a compliance default.
resource "aws_s3_bucket_lifecycle_configuration" "primary" {
  bucket     = aws_s3_bucket.primary.id
  depends_on = [aws_s3_bucket_versioning.primary]

  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Bucket policies
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "primary" {
  # SC-8: transmission confidentiality. Refuse anything not over TLS.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.primary.arn, "${aws_s3_bucket.primary.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # SC-28 enforcement: encryption becomes a condition of upload, not a
  # default applied on your behalf.
  #
  # WARNING: StringNotEquals evaluates TRUE when the key is absent, so this
  # denies any PutObject that does not explicitly carry the header, even one
  # the bucket default would have encrypted. Uploads must be explicit:
  #   aws s3 cp f s3://BUCKET/f --sse aws:kms --sse-kms-key-id "$KMS_ARN"
  statement {
    sid       = "DenyUnencryptedObjectUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.primary.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  # SC-28(1): the right algorithm with the wrong key is not the control.
  statement {
    sid       = "DenyWrongKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.primary.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.bucket.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "primary" {
  bucket = aws_s3_bucket.primary.id
  policy = data.aws_iam_policy_document.primary.json
}

data "aws_iam_policy_document" "log" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.log.arn, "${aws_s3_bucket.log.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # AU-3: the modern replacement for the log-delivery-write ACL.
  # SourceArn scopes the grant to exactly one source bucket; SourceAccount
  # stops another account using the S3 logging service as a confused deputy.
  statement {
    sid       = "AllowS3ServerAccessLogDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log.arn}/access-logs/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.primary.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

# NOTE: the SSE-enforcement denies are deliberately NOT on the log bucket.
# The S3 log delivery service sends no x-amz-server-side-encryption header,
# so adding them here silently breaks log delivery. Default bucket
# encryption still applies. This asymmetry is the easiest way to break
# this lab.
resource "aws_s3_bucket_policy" "log" {
  bucket = aws_s3_bucket.log.id
  policy = data.aws_iam_policy_document.log.json
}

# AU-3: wire the primary bucket's access logs into the log bucket.
# depends_on is genuinely required: the delivery grant must exist before S3
# accepts the logging configuration, and nothing here references the policy.
resource "aws_s3_bucket_logging" "primary" {
  bucket        = aws_s3_bucket.primary.id
  target_bucket = aws_s3_bucket.log.id
  target_prefix = "access-logs/"

  depends_on = [aws_s3_bucket_policy.log]
}
