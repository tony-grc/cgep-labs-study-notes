# variables.tf - Lab 5.2

variable "project_name" {
  type    = string
  default = "cgep-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.project_name))
    error_message = "project_name must be 3-21 lowercase alphanumerics or hyphens, starting with a letter."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "evidence_vault_arn" {
  type        = string
  description = "Lab 2.5 vault ARN. Data events are scoped to this bucket only. Set null to skip data events entirely (free, but object-level reads of the vault go unrecorded)."
  default     = null
}

variable "trail_retention_days" {
  type        = number
  description = "AU-11. 400 = a full annual audit cycle plus margin."
  default     = 400
  validation {
    condition     = var.trail_retention_days >= 90
    error_message = "trail_retention_days must be at least 90; shorter than a quarter is not an audit trail."
  }
}

variable "enable_security_hub" {
  type        = bool
  description = "Security Hub bills roughly $0.001 per check per month, about 300 checks for the NIST standard. Set false to deploy the trail alone."
  default     = true
}

variable "kms_deletion_window_days" {
  type    = number
  default = 7
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

variable "force_destroy_trail_bucket" {
  type        = bool
  description = "The trail writes its own logs into this bucket, so terraform destroy fails unless it can be emptied. True is right for a lab and wrong for production."
  default     = true
}
