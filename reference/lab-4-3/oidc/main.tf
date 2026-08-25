# main.tf - Lab 4.3: GitHub OIDC trust for the GRC gate
# Controls: IA-5 (no stored long-lived credentials), AC-6 (least privilege)

terraform {
  required_version = ">= 1.10"

  # Uncomment and fill from Lab 2.2's `terraform output -raw backend_block`.
  # backend "s3" {
  #   bucket       = "cgep-lab-tfstate-XXXXXXXX"
  #   key          = "labs/4-3-oidc/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }

  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project         = "cgep-lab"
      Environment     = "shared"
      ManagedBy       = "terraform"
      ComplianceScope = "cge-p-lab"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# AWS maintains the trust chain for this provider internally now, so the
# thumbprint is no longer load-bearing. The argument is still required.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# The plan role. Read-only, plus the state access a plan genuinely needs.
resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        # aud: the token must be addressed to AWS. A token minted for a
        # different audience cannot be replayed here.
        # sub: GitHub builds this string, and it now comes in two shapes.
        #
        #   classic     repo:OWNER/REPO:ref:refs/heads/main
        #   immutable   repo:OWNER@1234/REPO@5678:ref:refs/heads/main
        #
        # The second form appends GitHub's numeric account and repository IDs.
        # It exists because names can be renamed, transferred and re-registered,
        # while the IDs cannot, so a policy written against names alone trusts
        # whoever holds the name today. Repositories are being moved onto it.
        #
        # Matching only the classic form produces "Not authorized to perform
        # sts:AssumeRoleWithWebIdentity", which reads like a broken policy
        # rather than a claim that no longer looks the way you expected.
        #
        # Both patterns are listed because a condition value may be a list and
        # matches if ANY entry matches. The trailing * still covers every
        # trigger for this one repository. Never write repo:*:* - that trusts
        # every repository on GitHub.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",
            "repo:${var.github_org}@*/${var.github_repo}@*:*",
          ]
        }

        # The IDs, asserted exactly. This is what makes the wildcards above
        # safe: the sub match is by name, and these two pin the account and the
        # repository to the numbers GitHub will never reissue. Together they
        # are strictly tighter than the name-only policy this replaced.
        StringEquals = {
          "token.actions.githubusercontent.com:aud"                 = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:repository_owner_id" = var.github_owner_id
          "token.actions.githubusercontent.com:repository_id"       = var.github_repo_id
        }
      }
    }]
  })
}

# AC-6: read-only for the plan itself.
resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

# The state backend needs more than read: `terraform plan` writes a lock
# object and refreshes state. Without this the job fails at init, and the
# error mentions S3 rather than the role.
resource "aws_iam_role_policy" "state_access" {
  name = "tfstate-access"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.state_kms_arn
      },
    ]
  })
}
