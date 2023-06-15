## Google Cloud Security Command Center security findings to Slack notifications.

The Cloud Function [scc-to-slack-notifications](terraform/scc-to-slack-notifications.tf) will be trigged once Google Cloud Security Command Center publishes a message to the PubSub Topic "scc-findingsnotifier-topic" about a Security finding with a critical or high severity for active findings. 

Eenable SCC to publish findings to the Pubsub topic. This action requires permissions on the organizational level. 

Replace the [INSERT-ORG-ID] with the ORGID (Number) in the variables file.

```
    gcloud scc notifications create scc-critical-and-high-severity-findings-notify \
   --pubsub-topic projects/tf-scc-notifier/topics/scc-findingsnotifier-topic \
   --organization [INSERT-ORG-ID] \
   --filter "(severity=\"HIGH\" OR severity=\"CRITICAL\") AND state=\"ACTIVE\""
```

Filtering Security Command Center findings based on the most important projects is done by adjusting the 
filter option of the streaming_config:

```
  streaming_config {
    filter = "severity = \"HIGH\" OR severity= \"CRITICAL\" AND state = \"ACTIVE\""
        projects = [
           "project-1", 
           "project-2", 
           "project-3", 
           "project-4"
    ]
  }
}
```

***Create an Slack app and install it into your Workspace***
Navigate for your app to "OAuth Tokens for Your Workspace" to retrieve the Bot User OAuth Token. This token needs to be stored securely in the Secret Manager.

https://cloud.google.com/security-command-center/docs/how-to-enable-real-time-notifications#slack

***Cloud KMS***
Create KMS Keyring and Cryptokey in Cloud KMS. Use the create-kms-keyring-crypto.tf Terraform plan.

Set path for KMS Crypto key path:
Format: project-name/location/name-location/keyRings/keyring-name/cryptoKeys/key-name
Example: projects/playground-jliauw/locations/europe-west4/keyRings/europe-west4-generic/cryptoKeys/generic-key

***Grant usergroup or user permission to use kms encrypt (cryptoKeyEncrypter)***
resource "google_project_iam_member" "kms" {
  project = var.gcp_project_id
  role    = "roles/cloudkms.cryptoKeyEncrypter"
  member  = "group:name-of-group@domain.com"
  #member  = "user:jliauw@xebia.com"
  
}

***Grant user group permission to decrypt (cryptoKeyDecrypter) data with KMS***

resource "google_project_iam_member" "kms-decrypt" {
  project = var.gcp_project_id
  role    = "roles/cloudkms.cryptoKeyDecrypter"
  member  = "user:jliauw@xebia.com"
  # member  = "group:name-of-group@domain.com"

}

Cloud KMS resource location will be something like: projects/playground-jliauw/locations/europe-west4/keyRings/europe-west4-generic/cryptoKeys/generic-key

***Encrypt your secret with Cloud KMS***

Open Cloud Shell and run gcloud kms encrypt to encrypt the Slackbot token.

echo -n my-secret-password | gcloud kms encrypt \
--project my-project \
--location us-central1 \
--keyring my-key-ring \
--key my-crypto-key \
--plaintext-file - \
--ciphertext-file - \
| base64

Copy the output into the Terraform plan and replace the placeholder //COPY-CIPHER-TEXT-symmetric-key-VALUE// with the encrypted value. 

```
data "google_kms_secret" "slack_bot_token" {
  #  ## Token Slack bot for Workspace and GCP-SCC-Finding-Notifier app
  crypto_key = "playground-jliauw/locations/europe-west4/keyRings/europe-west4-generic/cryptoKeys/generic-key"
  ciphertext = "//COPY-CIPHER-TEXT-symmetric-key-VALUE//"
}
```

Cloud Function runs a Python script and is triggerd when a message is posted onto the PubSub topic. Cloud Function will send a notification message to the Slack channel #security-gcp-alerts. 

The Slack bot token is stored in Google Cloud Secret Manager and the secret in the Terraform plan is encrypted with Google Cloud KMS. In Slack we have the app GCP-SCC-Finding-Notifier installed into the Org Slack Workspace.

The source code can be found in /terraform/functions/scc-finding-slack-notifications
