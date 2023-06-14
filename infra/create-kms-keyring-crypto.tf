#------------------------------------------------------------------------------
# Create Google Cloud KMS Key Ring and Crypto Key
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

#################################################################################
# Deployment of required resource for creating Cloud KMS Key Ring and Crypto Key
#################################################################################

# Create Cloud KMS Key Ring 

resource "google_kms_key_ring" "kms-key" {
  # project  = var.gcp_project_id
  name     = "europe-west4-generic"
  location = "europe-west4"
}

# Create Cloud KMS Crypto Ring 

resource "google_kms_crypto_key" "crypto-key" {
  name     = "generic-key"
  key_ring = google_kms_key_ring.kms-key.id
}

# Grant user group permission to encrypt data with KMS

resource "google_project_iam_member" "kms" {
  project = var.gcp_project_id
  role    = "roles/cloudkms.cryptoKeyEncrypter"
  member  = "user:jliauw@xebia.com"
  # member  = "group:name-of-group@domain.com"

}
