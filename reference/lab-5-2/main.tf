# main.tf - Lab 5.2: AWS Security Services Baseline
# Controls: AU-2, AU-3, AU-6, AU-9, AU-11, AU-12, SC-8, SC-12, SC-13,
#           SC-28, AC-3, AC-6, RA-5, SI-4, CM-6, CM-8
#
# A mapping to argue with: CloudTrail log-file validation is often mapped to
# AU-10 (non-repudiation). The digest file protects the RECORD, not the binding
# of an actor to an action, so AU-9(3) and SI-7 are the stronger claim. Both
# are arguable. Being able to defend yours is the skill.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region

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
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  trail_name = "${var.project_name}-mgmt"
  trail_arn  = "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
}

# ---------------------------------------------------------------------------
# SC-12 / SC-13 / SC-28: the trail gets a CMK.
# Hold this bucket to the same standard as any other. It carries the audit
# record of the entire account, so a weaker baseline here than on a workload
# bucket is exactly backward.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "trail" {
  description             = "CMK for CloudTrail logs"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.trail_kms.json
}

resource "aws_kms_alias" "trail" {
  name          = "alias/${var.project_name}-cloudtrail"
  target_key_id = aws_kms_key.trail.key_id
}

data "aws_iam_policy_document" "trail_kms" {
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

  # CloudTrail must be able to encrypt log files with this key.
  statement {
    sid       = "AllowCloudTrailEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Athena and your analysts must be able to read them back. Without this,
  # queries fail with HIVE_CURSOR_ERROR on decryption.
  statement {
    sid       = "AllowAccountDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

# ---------------------------------------------------------------------------
# The trail bucket, on the shared baseline
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  bucket        = "${var.project_name}-cloudtrail-${random_id.suffix.hex}"
  force_destroy = var.force_destroy_trail_bucket
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AU-11: 400 days is deliberate. A full annual audit cycle plus margin, so a
# question in month thirteen about month one still has logs behind it.
# Glacier Instant Retrieval at 90 days: written constantly, read rarely, must
# be readable immediately when read. That is exactly the storage class.
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket     = aws_s3_bucket.trail.id
  depends_on = [aws_s3_bucket_versioning.trail]

  rule {
    id     = "expire-trail-logs"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.trail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# Trail bucket policy. The aws:SourceArn conditions are confused-deputy
# protection: without them another account's trail could be pointed here.
# Same pattern as the S3 access-log grant in Lab 2.3, which is why v2 uses a
# policy there instead of an ACL.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
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

  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

# ---------------------------------------------------------------------------
# AU-2 / AU-12: the trail. AU-9 / SI-7 via log-file validation digests.
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "mgmt" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.trail.arn

  # AU-3: object-level events on the evidence vault ONLY.
  #
  # Skipping data events leaves object-level access to the vault unrecorded,
  # and that is the gap an insider uses: read the evidence, learn what the
  # auditor will see, and no record exists that you looked. Management events
  # show the bucket being CREATED, never that it was READ.
  #
  # Scoping to one bucket is the honest middle. Account-wide data events are
  # a real budget decision at $0.10 per 100k events.
  dynamic "advanced_event_selector" {
    for_each = var.evidence_vault_arn == null ? [] : [var.evidence_vault_arn]
    content {
      name = "S3 data events on the evidence vault"

      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = ["${advanced_event_selector.value}/"]
      }
    }
  }

  advanced_event_selector {
    name = "All management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

# ---------------------------------------------------------------------------
# RA-5 / SI-4: Security Hub
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${var.aws_region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# AU-6: audit review. The control most often claimed on the strength of
# collection alone.
# Collecting logs is AU-3 plus AU-11. REVIEWING them is AU-6, and it needs
# something that reads them. See queries/ for the three that constitute a
# review, and the README for why running them once is `partial`, not
# `implemented`.
# ---------------------------------------------------------------------------
resource "aws_glue_catalog_database" "trail" {
  name = replace("${var.project_name}_grc", "-", "_")
}

resource "aws_athena_workgroup" "grc" {
  name = "${var.project_name}-grc"

  configuration {
    enforce_workgroup_configuration = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.trail.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.trail.arn
      }
    }
  }
}
