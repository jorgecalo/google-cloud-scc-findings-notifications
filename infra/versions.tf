terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # The decrypted Slack bot token is stored in state. Use a remote backend
  # with restricted access and encryption. Example:
  # backend "gcs" {
  #   bucket = "my-terraform-state-bucket"
  #   prefix = "scc-slack-notifier"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
