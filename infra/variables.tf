###############################################################################
# General variables for project
###############################################################################

variable "gcp_org_id" {
  type    = string
  default = "?"
}

variable "gcp_project_id" {
  type    = string
  default = "?"
}

variable "labels_app" {
  type    = string
  default = "?"
}

variable "labels_environment" {
  type    = string
  default = "?"
}

variable "gcp_region" {
  description = "Default region for Google provider"
  default     = "europe-west1" #Cloud Function closest region is Europe West 1 (BE). CF is not available in Europe West4 (NL)
  type        = string
}

variable "gcp_region-2" {
  description = "Additional region for Google provider"
  default     = "europe-west3" #Backup region for storage Secret Manager
  type        = string
}

###############################################################################
# Variables for specific resources
###############################################################################

variable "gcp_pubsub_name_topic" {
  description = "PubSub name topic"
  default     = "?"
  type        = string
}

variable "gcp_pubsub_name_subscription" {
  description = "PubSub name subscription"
  default     = "?"
  type        = string
}

variable "gcp_cloudstorage_name_bucket" {
  description = "Name Cloud Storage bucket"
  default     = "?"
  type        = string
}

variable "gcp_cloudstorage_name_zipfile" {
  description = "Name zip file stored in Cloud Storage Bucket"
  default     = "?"
  type        = string
}

variable "gcp_cloudfunction_name" {
  description = "?"
  default     = "?"
  type        = string
}
