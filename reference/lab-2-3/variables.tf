# variables.tf - Lab 2.3
#
# Validation blocks are PREVENTIVE controls: they reject bad input at plan
# time, before anything reaches AWS. Detecting a mistyped Environment tag in
# a Config rule three hours later is detective, and strictly weaker.

variable "project_name" {
  type        = string
  description = "Short project identifier. Becomes part of bucket names and the Project tag."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment. Drives the Environment tag and downstream policy decisions."
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  type        = string
  description = "Region. Must match the region of the Lab 2.2 state backend."
  default     = "us-east-1"
}

variable "bucket_suffix" {
  type        = string
  description = "Optional suffix to force a specific bucket name. Defaults to a random_id."
  default     = null
}

variable "kms_deletion_window_days" {
  type        = number
  description = "Waiting period before a scheduled CMK deletion completes. AWS allows 7-30."
  default     = 7
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "log_retention_days" {
  type        = number
  description = "AU-11. How long access-log objects are kept before expiry."
  default     = 90
  validation {
    condition     = var.log_retention_days >= 1
    error_message = "log_retention_days must be at least 1."
  }
}

variable "noncurrent_version_retention_days" {
  type        = number
  description = "How long superseded object versions survive before expiry."
  default     = 30
}
