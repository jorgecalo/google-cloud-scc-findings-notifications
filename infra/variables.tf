###############################################################################
# General variables for project
###############################################################################

variable "gcp_project_id" {
  type    = string
  default = "?"
}

variable "gcp_region" {
  description = "Default region for google provider"
  default     = "europe-west1"
  type        = string
}

###############################################################################
# Variables for ?SPECIFIC SERVICE?
###############################################################################
