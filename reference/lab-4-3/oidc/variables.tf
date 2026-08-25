variable "github_org" {
  type        = string
  description = "GitHub organization or user that owns the repository."
  validation {
    # An EMPTY string is the dangerous case, not a missing one. Terraform stops
    # on a variable that was never set; it accepts "" and builds from it, and
    # the OIDC sub condition becomes "repo:/your-repo:*", which no real token
    # can match. The role is then un-assumable and the failure surfaces in CI
    # as "invalid identity token", which sends you looking at the wrong thing.
    condition     = length(var.github_org) > 0
    error_message = "github_org must not be empty. Set TF_VAR_github_org in cgep.env."
  }
}

variable "github_repo" {
  type        = string
  description = "Repository name. The trust policy is bound to this one repo."
  validation {
    # An EMPTY string is the dangerous case, not a missing one. Terraform stops
    # on a variable that was never set; it accepts "" and builds from it, and
    # the OIDC sub condition becomes "repo:/your-repo:*", which no real token
    # can match. The role is then un-assumable and the failure surfaces in CI
    # as "invalid identity token", which sends you looking at the wrong thing.
    condition     = length(var.github_repo) > 0
    error_message = "github_repo must not be empty. Set TF_VAR_github_repo in cgep.env."
  }
}

variable "state_bucket" {
  type        = string
  description = "Lab 2.2 state bucket name."
}

variable "state_kms_arn" {
  type        = string
  description = "Lab 2.2 state CMK ARN."
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}
