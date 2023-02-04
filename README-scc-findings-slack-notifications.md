## Google Cloud Security Command Center security findings to Slack notifications.

The Cloud Function [scc-to-slack-notifications](terraform/scc-to-slack-notifications.tf) will be trigged once Google Cloud Security Command Center publishes a message to the PubSub Topic "scc-findingsnotifier-topic" about a Security finding with a critical or high severity for active findings. 

Eenable SCC to publish findings to the Pubsub topic. This action requires permissions on the organizational level. 

Replace the [INSERT-ORG-ID] with the ORGID (Number).

```
    gcloud scc notifications create scc-critical-and-high-severity-findings-notify \
   --pubsub-topic projects/tf-scc-notifier/topics/scc-findingsnotifier-topic \
   --organization [INSERT-ORG-ID] \
   --filter "(severity=\"HIGH\" OR severity=\"CRITICAL\") AND state=\"ACTIVE\""

```

Cloud Function runs a Python script and is triggerd when a message is posted onto the PubSub topic. Cloud Function will send a notification message to the Slack channel #security-gcp-alerts. 

The Slack bot token is stored in Google Cloud Secret Manager and the secret in the Terraform plan is encrypted with Google Cloud KMS. In Slack we have the app GCP-SCC-Finding-Notifier installed into the Mollie Workspace.

The source code can be found in /terraform/functions/scc-finding-slack-notifications

