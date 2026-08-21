# variables.tf - Lab 2.5

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

variable "lock_mode" {
  type        = string
  description = "GOVERNANCE for lab work; COMPLIANCE for real evidence."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "retention_days" {
  type        = number
  description = "Default retention applied to every uploaded object."
  default     = 1

  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 3650
    error_message = "retention_days must be between 1 and 3650."
  }

  # COMPLIANCE mode is unbypassable by anyone including root, so a long
  # retention has to be a deliberate act rather than a default.
  validation {
    condition     = var.lock_mode != "COMPLIANCE" || var.retention_days <= 7 || var.acknowledge_compliance_mode
    error_message = "COMPLIANCE mode beyond 7 days requires acknowledge_compliance_mode = true. You will not be able to delete these objects, ever, until retention expires."
  }
}

variable "acknowledge_compliance_mode" {
  type        = bool
  description = "Set true only if you intend evidence to outlive your ability to delete it."
  default     = false
}

variable "kms_deletion_window_days" {
  type    = number
  default = 7
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}
