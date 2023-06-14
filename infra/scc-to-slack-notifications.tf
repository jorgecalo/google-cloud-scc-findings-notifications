#------------------------------------------------------------------------------
# Google Cloud Security Command Center finding notifications to Slack v1.1.0
#------------------------------------------------------------------------------

###############################################################################
# Enable APIs - Enable required APIs for deployment
###############################################################################

resource "google_project_service" "compute" {
  service                    = "compute.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "service_networking" {
  service                    = "servicenetworking.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_project_service" "cloudkms" {
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

###############################################################################
# Deployment of required resource for running SCC to Slack source code
###############################################################################

# Create Cloud KMS Key Ring 

resource "google_kms_key_ring" "keyring-europe-west4" {
  project  = var.gcp_project_id
  name     = "keyring-europe-west4"
  location = "europe-west4"
}

# Create Cloud KMS Crypto Ring 

resource "google_kms_crypto_key" "kms-cryptokey" {
  name     = "kms-cryptokey"
  key_ring = google_kms_key_ring.keyring-europe-west4.self_link
}

# Create Pubsub topic. SCC will publish the findings on this topic. Defined project in resource.
resource "google_pubsub_topic" "sccfindings" {
  name    = "scc-findingsnotifier-topic"
  project = var.gcp_project_id
  message_storage_policy {
    allowed_persistence_regions = [
      "europe-west1",
      "europe-west4",
    ]
  }
}

resource "google_scc_notification_config" "custom_notification_config" {
  config_id    = "security-scc-notify-config"
  organization = var.gcp_org_id
  description  = "Security team Custom Cloud SCC Finding Notification Configuration"
  pubsub_topic = google_pubsub_topic.sccfindings.id

  streaming_config {
    filter = "severity = \"HIGH\" OR severity= \"CRITICAL\" AND state = \"ACTIVE\""
    #HERE YOU CAN FILTER ON PROJECTS WHICH TO INCLUDE. Figure out the filtering for multiple projects AND "..."
    # projects = [
    #      "project-1", 
    #      "project-2", 
    #      "project-3", 
    #      "project-4"
    #]

  }
}

# Create pubsub subscription that notifies Cloud Function.
resource "google_pubsub_subscription" "sccfinding-cf-sub" {
  project = var.gcp_project_id
  name    = "sccfinding-subscription"
  topic   = google_pubsub_topic.sccfindings.name

  # 20 minutes
  message_retention_duration = "1200s"
  retain_acked_messages      = true

  ack_deadline_seconds = 20

  expiration_policy {
    ttl = "300000.5s"
  }
  retry_policy {
    minimum_backoff = "10s"
  }

  enable_message_ordering = false
}

#Create Google Storage bucket that will host source code in region Europe West1
resource "google_storage_bucket" "function_bucket" {
  project  = var.gcp_project_id
  name     = "scc-slack-notifier-cf-bucket"
  location = var.gcp_region
}

#Generate an archive of the source code compressed as a .zip file. Source is stored in the Terraform directory /app/
data "archive_file" "source" {
  type        = "zip"
  source_dir  = "${path.root}/app/scc-finding-slack-notifications"
  output_path = "${path.root}/cf-scc-notification.zip"
}

# Add source code zip to bucket
resource "google_storage_bucket_object" "zip" {
  # Append file MD5 to force bucket to be recreated
  name         = "cf-scc-notification.zip"
  bucket       = google_storage_bucket.function_bucket.name
  source       = data.archive_file.source.output_path
  content_type = "application/zip"
}

# Create Cloud Function with Python Runtime.
resource "google_cloudfunctions_function" "cf" {
  project               = var.gcp_project_id
  region                = var.gcp_region
  name                  = "scc-slack-notifier"
  description           = "Security Command Center findings notifier to Slack"
  runtime               = "python310"
  service_account_email = google_service_account.sccnotifier.email

  timeout             = 540
  available_memory_mb = 256
  max_instances       = 1
  ingress_settings    = "ALLOW_INTERNAL_AND_GCLB"

  environment_variables = {
    SLACK_BOT_TOKEN = format("%s/versions/latest", google_secret_manager_secret.slack_bot_token.id)
  }

  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.zip.name

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = google_pubsub_topic.sccfindings.id
    failure_policy {
      retry = true
    }

  }
  labels = {
    "app"         = var.labels_app
    "environment" = var.labels_environment
    "tf"          = true
  }

  entry_point = "send_slack_chat_notification"
}

#Create Service Account. Defined project in resource.
resource "google_service_account" "sccnotifier" {
  project      = var.gcp_project_id
  display_name = "The sccnotifier service"
  account_id   = "sccnotifier"
}

#Add role IAM ServiceAccountUser to created Service Account.
resource "google_service_account_iam_member" "sccnotifier_service_account_user_sccnotifier" {
  service_account_id = google_service_account.sccnotifier.name
  member             = format("serviceAccount:%s", google_service_account.sccnotifier.email)
  role               = "roles/iam.serviceAccountUser"
}

# Create Secret Manager resource for Slack Bot token. Defined project in resource.
resource "google_secret_manager_secret" "slack_bot_token" {
  project   = var.gcp_project_id
  secret_id = "sccnotifier-slack-bot-token"
  replication {
    user_managed {
      replicas {
        location = var.gcp_region
      }
      replicas {
        location = var.gcp_region-2
      }
    }

  }
}

#Secret Manager grant access right to secret.
resource "google_secret_manager_secret_iam_binding" "slack_bot_token" {
  role      = "roles/secretmanager.secretAccessor"
  secret_id = google_secret_manager_secret.slack_bot_token.id
  members = [
    format("serviceAccount:%s", google_service_account.sccnotifier.email)
  ]
}

resource "google_secret_manager_secret_version" "slack_bot_token" {
  secret      = google_secret_manager_secret.slack_bot_token.id
  secret_data = data.google_kms_secret.slack_bot_token.plaintext

}

data "google_kms_secret" "slack_bot_token" {
  #  ## Token Slack bot for Workspace and GCP-SCC-Finding-Notifier app
  crypto_key = "[INSERT-PROJECT-NAME]/europe-west4/audit-global-generic/audit-generic"
  ciphertext = "//COPY-CIPHER-TEXT-symmetric-key-VALUE//"
}
