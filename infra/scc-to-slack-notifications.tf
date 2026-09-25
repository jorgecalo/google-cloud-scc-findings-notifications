#------------------------------------------------------------------------------
# Google Cloud Security Command Center finding notifications to Slack v2.0.0
# Stage 2: apply after the kms module in ./kms.
#------------------------------------------------------------------------------

data "google_project" "this" {
  project_id = var.project_id
}

###############################################################################
# Enable required APIs
###############################################################################

locals {
  services = toset([
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "eventarc.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "securitycenter.googleapis.com",
    "storage.googleapis.com",
  ])

  pubsub_service_agent = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

resource "google_project_service" "services" {
  for_each           = local.services
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

###############################################################################
# Pub/Sub topic and SCC notification config
###############################################################################

resource "google_pubsub_topic" "sccfindings" {
  project = var.project_id
  name    = var.topic_name

  message_storage_policy {
    allowed_persistence_regions = var.pubsub_allowed_persistence_regions
  }

  depends_on = [google_project_service.services]
}

# SCC v2 API. Configs created with v1 are not visible in v2, so delete any
# existing v1 config with the same purpose to avoid duplicate Slack messages.
resource "google_scc_v2_organization_notification_config" "slack" {
  config_id    = var.notification_config_id
  organization = var.org_id
  location     = "global"
  description  = "Sends active, unmuted high and critical SCC findings to Slack"
  pubsub_topic = google_pubsub_topic.sccfindings.id

  streaming_config {
    filter = var.notification_filter
  }

  depends_on = [google_project_service.services]
}

###############################################################################
# Service accounts and IAM
###############################################################################

# Runtime identity of the function and identity of the Eventarc trigger.
resource "google_service_account" "sccnotifier" {
  project      = var.project_id
  account_id   = "sccnotifier"
  display_name = "SCC to Slack notifier runtime"
}

# Identity used by Cloud Build to build the function.
resource "google_service_account" "build" {
  project      = var.project_id
  account_id   = "sccnotifier-build"
  display_name = "SCC to Slack notifier build"
}

resource "google_project_iam_member" "build_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = google_service_account.build.member
}

resource "google_project_iam_member" "trigger_event_receiver" {
  project = var.project_id
  role    = "roles/eventarc.eventReceiver"
  member  = google_service_account.sccnotifier.member
}

# Lets Pub/Sub mint tokens for authenticated push to the function. Needed for
# projects created before April 2021, harmless for newer projects.
resource "google_service_account_iam_member" "pubsub_token_creator" {
  service_account_id = google_service_account.sccnotifier.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.pubsub_service_agent

  depends_on = [google_project_service.services]
}

# The trigger identity may invoke only this function's Cloud Run service.
resource "google_cloud_run_v2_service_iam_member" "trigger_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloudfunctions2_function.cf.name
  role     = "roles/run.invoker"
  member   = google_service_account.sccnotifier.member
}

###############################################################################
# Slack bot token in Secret Manager
###############################################################################

data "google_kms_secret" "slack_bot_token" {
  crypto_key = var.kms_crypto_key_id
  ciphertext = var.slack_bot_token_ciphertext
}

resource "google_secret_manager_secret" "slack_bot_token" {
  project   = var.project_id
  secret_id = "sccnotifier-slack-bot-token"

  replication {
    user_managed {
      dynamic "replicas" {
        for_each = var.secret_replica_locations
        content {
          location = replicas.value
        }
      }
    }
  }

  depends_on = [google_project_service.services]
}

resource "google_secret_manager_secret_version" "slack_bot_token" {
  secret      = google_secret_manager_secret.slack_bot_token.id
  secret_data = data.google_kms_secret.slack_bot_token.plaintext
}

resource "google_secret_manager_secret_iam_member" "slack_bot_token" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_bot_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.sccnotifier.member
}

###############################################################################
# Optional Google Threat Intelligence (GTI) API key in Secret Manager
###############################################################################

data "google_kms_secret" "gti_api_key" {
  count      = var.gti_api_key_ciphertext != "" ? 1 : 0
  crypto_key = var.kms_crypto_key_id
  ciphertext = var.gti_api_key_ciphertext
}

resource "google_secret_manager_secret" "gti_api_key" {
  count     = var.gti_api_key_ciphertext != "" ? 1 : 0
  project   = var.project_id
  secret_id = "sccnotifier-gti-api-key"

  replication {
    user_managed {
      dynamic "replicas" {
        for_each = var.secret_replica_locations
        content {
          location = replicas.value
        }
      }
    }
  }

  depends_on = [google_project_service.services]
}

resource "google_secret_manager_secret_version" "gti_api_key" {
  count       = var.gti_api_key_ciphertext != "" ? 1 : 0
  secret      = google_secret_manager_secret.gti_api_key[0].id
  secret_data = data.google_kms_secret.gti_api_key[0].plaintext
}

resource "google_secret_manager_secret_iam_member" "gti_api_key" {
  count     = var.gti_api_key_ciphertext != "" ? 1 : 0
  project   = var.project_id
  secret_id = google_secret_manager_secret.gti_api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.sccnotifier.member
}

###############################################################################
# Function source
###############################################################################

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "google_storage_bucket" "function_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-scc-notifier-src-${random_id.bucket_suffix.hex}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true

  depends_on = [google_project_service.services]
}

data "archive_file" "source" {
  type        = "zip"
  source_dir  = "${path.module}/../app/scc-finding-slack-notifications"
  output_path = "${path.module}/.build/function-source.zip"
  excludes    = ["__pycache__", "**/__pycache__/**", "**/*.pyc", ".venv", "**/.venv/**"]
}

# The MD5 in the object name makes every code change redeploy the function.
resource "google_storage_bucket_object" "source" {
  name         = "function-source-${data.archive_file.source.output_md5}.zip"
  bucket       = google_storage_bucket.function_source.name
  source       = data.archive_file.source.output_path
  content_type = "application/zip"
}

###############################################################################
# Cloud Run function (2nd gen)
###############################################################################

resource "google_cloudfunctions2_function" "cf" {
  project     = var.project_id
  location    = var.region
  name        = var.function_name
  description = "Security Command Center findings notifier to Slack"

  build_config {
    runtime         = var.function_runtime
    entry_point     = "send_slack_chat_notification"
    service_account = google_service_account.build.id

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.source.name
      }
    }
  }

  service_config {
    available_memory               = "256M"
    timeout_seconds                = 60
    max_instance_count             = var.max_instance_count
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true
    service_account_email          = google_service_account.sccnotifier.email

    environment_variables = {
      SLACK_CHANNEL          = var.slack_channel
      ALLOWED_PROJECTS       = join(",", var.allowed_projects)
      ALLOWED_EXPLOITABILITY = join(",", var.allowed_exploitability)
      ALLOWED_CVE_IMPACT     = join(",", var.allowed_cve_impact)
      DEDUP_WINDOW_SECONDS   = tostring(var.cve_dedup_window_seconds)
      MAX_EVENT_AGE_SECONDS  = tostring(var.max_event_age_seconds)
    }

    secret_environment_variables {
      key        = "SLACK_BOT_TOKEN"
      project_id = var.project_id
      secret     = google_secret_manager_secret.slack_bot_token.secret_id
      version    = "latest"
    }

    dynamic "secret_environment_variables" {
      for_each = var.gti_api_key_ciphertext != "" ? [1] : []
      content {
        key        = "GTI_API_KEY"
        project_id = var.project_id
        secret     = google_secret_manager_secret.gti_api_key[0].secret_id
        version    = "latest"
      }
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.sccfindings.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.sccnotifier.email
  }

  depends_on = [
    google_project_service.services,
    google_project_iam_member.build_builder,
    google_project_iam_member.trigger_event_receiver,
    google_secret_manager_secret_iam_member.slack_bot_token,
    google_secret_manager_secret_version.slack_bot_token,
    google_secret_manager_secret_iam_member.gti_api_key,
    google_secret_manager_secret_version.gti_api_key,
  ]
}
