###############################################################################
# General variables for project
###############################################################################

variable "gcp_org_id" {
  type    = string
  default = "	362295884660"
}

variable "gcp_project_id" {
  type    = string
  default = "playground-jliauw"
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

# variable "gcp_pubsub_name_topic" {
#   description = "PubSub name topic"
#   default     = "?"
#   type        = string
# }

# variable "gcp_pubsub_name_subscription" {
#   description = "PubSub name subscription"
#   default     = "?"
#   type        = string
# }

variable "gcp_cloudstorage_name_bucket" {
  description = "Name Cloud Storage bucket"
  default     = "scc-slack-notifier-cf-bucket"
  type        = string
}

variable "scc_notification_filter" {
  description = "SCC streaming notification filter. Covers all ACTIVE CRITICAL/HIGH non-CVE findings (Threats, Misconfigurations, Toxic Combinations, non-CVE Vulnerabilities) while strictly filtering CVE findings to WIDE/AVAILABLE/CONFIRMED exploitability and CRITICAL/HIGH impact."
  type        = string
  default     = "state = \"ACTIVE\" AND (severity = \"HIGH\" OR severity = \"CRITICAL\") AND (finding_class != \"VULNERABILITY\" OR vulnerability.cve.id = \"\" OR ((vulnerability.cve.exploitation_activity = \"WIDE\" OR vulnerability.cve.exploitation_activity = \"AVAILABLE\" OR vulnerability.cve.exploitation_activity = \"CONFIRMED\") AND (vulnerability.cve.impact = \"CRITICAL\" OR vulnerability.cve.impact = \"HIGH\")))"
}

variable "cve_dedup_window_seconds" {
  description = "Cooldown window in seconds to deduplicate repeated alerts for the same CVE in the Cloud Function"
  type        = string
  default     = "3600"
}

