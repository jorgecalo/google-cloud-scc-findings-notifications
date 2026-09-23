###############################################################################
# General
###############################################################################

variable "org_id" {
  description = "Numeric Google Cloud organization ID where SCC is activated."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.org_id))
    error_message = "org_id must contain digits only, without spaces or tabs."
  }
}

variable "project_id" {
  description = "Project that hosts the Pub/Sub topic, function, secret and bucket."
  type        = string
}

variable "region" {
  description = "Region for the Cloud Run function, Eventarc trigger and source bucket."
  type        = string
  default     = "europe-west1"
}

###############################################################################
# Security Command Center
###############################################################################

variable "notification_config_id" {
  description = "ID of the SCC notification config. Must be unique in the organization."
  type        = string
  default     = "scc-slack-notifier"
}

variable "notification_filter" {
  description = "SCC findings filter. Default: active, unmuted HIGH and CRITICAL findings."
  type        = string
  default     = "(severity=\"HIGH\" OR severity=\"CRITICAL\") AND state=\"ACTIVE\" AND -mute=\"MUTED\""
}

variable "allowed_projects" {
  description = "Optional project IDs or display names to notify on. Empty means all projects."
  type        = list(string)
  default     = []
}

###############################################################################
# Pub/Sub
###############################################################################

variable "topic_name" {
  description = "Pub/Sub topic SCC publishes findings to."
  type        = string
  default     = "scc-findingsnotifier-topic"
}

variable "pubsub_allowed_persistence_regions" {
  description = "Regions where Pub/Sub may store messages."
  type        = list(string)
  default     = ["europe-west1", "europe-west4"]
}

###############################################################################
# Slack and secrets
###############################################################################

variable "slack_channel" {
  description = "Slack channel ID (recommended, for example C0123456789) or channel name. Invite the bot to the channel."
  type        = string
  default     = "security-gcp-alerts"
}

variable "kms_crypto_key_id" {
  description = "Crypto key ID from the kms module output crypto_key_id."
  type        = string
}

variable "slack_bot_token_ciphertext" {
  description = "Base64 KMS ciphertext of the Slack bot token. See the kms module output encrypt_command."
  type        = string
  sensitive   = true

  validation {
    condition     = !startswith(var.slack_bot_token_ciphertext, "REPLACE-") && can(regex("^[A-Za-z0-9+/]+={0,2}$", var.slack_bot_token_ciphertext))
    error_message = "Replace the placeholder with the single line base64 KMS ciphertext of the Slack bot token."
  }
}

variable "secret_replica_locations" {
  description = "Secret Manager replica locations for the Slack bot token."
  type        = list(string)
  default     = ["europe-west1", "europe-west3"]
}

###############################################################################
# Function
###############################################################################

variable "function_name" {
  description = "Name of the Cloud Run function."
  type        = string
  default     = "scc-slack-notifier"
}

variable "function_runtime" {
  description = "Python runtime. python313 is supported until October 2029."
  type        = string
  default     = "python313"
}

variable "max_instance_count" {
  description = "Maximum function instances. Keep low to respect Slack rate limits."
  type        = number
  default     = 3
}

variable "max_event_age_seconds" {
  description = "Events older than this are dropped instead of being retried."
  type        = number
  default     = 3600
}
