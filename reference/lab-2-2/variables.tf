# variables.tf - Lab 2.2

variable "project_name" {
  type        = string
  description = "Short project identifier. Becomes part of the bucket name."
  default     = "cgep-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "aws_region" {
  type        = string
  description = "Region for the state backend. Every workspace must use the same one."
  default     = "us-east-1"
}

variable "kms_deletion_window_days" {
  type        = number
  description = "Waiting period before a scheduled key deletion completes. AWS allows 7-30."
  default     = 7
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "state_version_retention_days" {
  type        = number
  description = "How long superseded state versions are kept before expiry."
  default     = 90
}
