# ------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ------------------------------------------------------------------------------
variable "default_zones" {
  description = "The default zone to use for resources"
  type        = list(string)
}

variable "environment" {
  description = "The environment this module will run in"
  type        = string
}

variable "region" {
  description = "The region this module will run in"
  type        = string
}

variable "project_id" {
  description = "The project this module will run in"
  type        = string
}


# ------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ------------------------------------------------------------------------------

variable "recapatcha_allowed_domains" {
  description = "ReCaptcha allowed domains for each environment"
  type        = list(string)
  default     = []
}
