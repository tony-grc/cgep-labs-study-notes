variable "github_org" {
  type        = string
  description = "GitHub organization or user that owns the repository."
}

variable "github_repo" {
  type        = string
  description = "Repository name. The trust policy is bound to this one repo."
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
