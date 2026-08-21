# main.tf - Lab 2.2: Remote State Backend (AWS)
# Bootstrap workspace. Deliberately uses LOCAL state; see README.md.
# Controls: SC-8, SC-12, SC-13, SC-28, AC-3, AC-6, CP-9, AU-11, CM-6, CM-8

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  # No backend block. This workspace is deliberately local.
}

provider "aws" {
  region = var.aws_region

  # CM-6 / CM-8: required tags on every taggable resource.
  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = "shared"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  bucket_name = "${var.project_name}-tfstate-${random_id.suffix.hex}"
}

# ---------------------------------------------------------------------------
# SC-12 / SC-13: customer-managed key, rotation enabled.
# State is a secrets store. It gets a key you control.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "tfstate" {
  description             = "CMK for Terraform state at rest"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/${var.project_name}-tfstate"
  target_key_id = aws_kms_key.tfstate.key_id
}

data "aws_iam_policy_document" "kms" {
  # Omitting this makes the key permanently unmanageable. AWS allows it.
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
}

resource "aws_s3_bucket" "tfstate" {
  bucket = local.bucket_name
}

# AC-3 / AC-6: ACLs disabled. AWS default since April 2023, and an
# ACL-enabled bucket is itself a Security Hub finding (S3.12).
resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SC-28: encryption at rest with our CMK. bucket_key_enabled cuts KMS
# request charges by up to 99%; state is written on every apply.
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
    bucket_key_enabled = true
  }
}

# CP-9 / SI-7: mandatory here. A truncated state file is recoverable only
# if the prior version survived.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: all four flags. Two axes (ACL vs policy) by two states (new vs existing).
resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-11: keep old state versions long enough to recover, not forever.
resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket     = aws_s3_bucket.tfstate.id
  depends_on = [aws_s3_bucket_versioning.tfstate]

  rule {
    id     = "expire-noncurrent-state"
    status = "Enabled"

    # An empty filter applies the rule to every object. Provider 5.x errors
    # if a rule has neither filter nor prefix.
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = var.state_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# SC-8: refuse any request that did not arrive over TLS.
data "aws_iam_policy_document" "tfstate" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]

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
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate.json
}
