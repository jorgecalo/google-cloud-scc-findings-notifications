# Google Cloud Security Command Center findings to Slack

Security Command Center (SCC) publishes active, unmuted HIGH and CRITICAL findings to a Pub/Sub topic. An Eventarc trigger runs a Cloud Run function (2nd gen, Python 3.13) that formats each finding and posts it to a Slack channel.

```
SCC notification config (v2 API) -> Pub/Sub topic -> Eventarc -> Cloud Run function -> Slack chat.postMessage
```

## Repository layout

| Path | Purpose |
|---|---|
| [infra/kms/](infra/kms/) | Stage 1. KMS key ring and key that encrypt the Slack bot token. |
| [infra/](infra/) | Stage 2. Topic, SCC notification config, secret, service accounts and function. |
| [app/scc-finding-slack-notifications/](app/scc-finding-slack-notifications/) | Function source and the Slack Block Kit template. |
| [tests/](tests/) | Unit tests and sample SCC notifications. |

## Prerequisites

- Terraform 1.9 or newer and the gcloud CLI.
- SCC activated at organization level.
- The identity that runs Terraform needs:
  - `roles/securitycenter.notificationConfigEditor` or `roles/securitycenter.admin` on the organization.
  - `roles/pubsub.admin` on the project, so SCC can grant its service agent publish rights on the topic.
  - Rights to enable APIs, create service accounts, grant IAM, and create functions, secrets and buckets in the project. `roles/owner` on a dedicated project is the simplest option.
  - `roles/iam.serviceAccountUser` on the two service accounts Terraform creates.
  - `roles/cloudkms.cryptoKeyDecrypter` on the KMS key. Stage 1 grants this through `decrypter_members`.

## Step 1: Create the Slack app

1. Create a Slack app and add the `chat:write` bot scope.
2. Install it into your workspace and copy the **Bot User OAuth Token**, which starts with `xoxb-`.
3. Invite the bot to the target channel with `/invite @your-app`.
4. Copy the channel ID from the channel details. An ID is more reliable than a name.

## Step 2: Create the KMS key

```bash
cd infra/kms
cp terraform.tfvars.example terraform.tfvars   # fill in project and members
terraform init
terraform apply
```

The key has `prevent_destroy` set, because destroying it makes the stored ciphertext unrecoverable.

## Step 3: Encrypt the Slack bot token

Run the command from the `encrypt_command` output. Read the token without echoing it to your shell history:

```bash
read -rs SLACK_BOT_TOKEN && export SLACK_BOT_TOKEN
terraform output -raw encrypt_command | sh
unset SLACK_BOT_TOKEN
```

The result is a single line of base64 ciphertext.

## Step 4: Deploy the notifier

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
```

Fill in `terraform.tfvars`:

- `org_id` and `project_id`.
- `kms_crypto_key_id` from the stage 1 output `crypto_key_id`.
- `slack_bot_token_ciphertext`. Replace the placeholder `REPLACE-WITH-KMS-CIPHERTEXT-OF-SLACK-BOT-TOKEN` with the ciphertext from step 3. Terraform refuses to plan while the placeholder is still there.
- `slack_channel`, preferably the channel ID.

Then deploy:

```bash
terraform init
terraform plan
terraform apply
```

Terraform decrypts the token, stores it in Secret Manager and injects it into the function as the `SLACK_BOT_TOKEN` environment variable.

**Protect the Terraform state.** The decrypted token is stored in state. Configure the commented `gcs` backend in [infra/versions.tf](infra/versions.tf) on a bucket with restricted access before the first apply.

## Filtering

The default filter sends active, unmuted HIGH and CRITICAL findings:

```
(severity="HIGH" OR severity="CRITICAL") AND state="ACTIVE" AND -mute="MUTED"
```

Change it with `notification_filter`. Always use parentheses around `OR` groups. The filter accepts the same syntax as the SCC `findings.list` method, for example `category="OPEN_FIREWALL"` or `-parent="organizations/ORG/sources/SOURCE"`.

To notify only on specific projects, set `allowed_projects` to a list of project IDs or display names. The function skips findings from other projects.

**Create the notification config only once.** Terraform creates it with the SCC v2 API. Do not also create one with `gcloud scc notifications create`, or every finding is posted twice. Configs made with the v1 API are not visible in the v2 API, so delete any old v1 config:

```bash
gcloud scc notifications list --organization=ORG_ID
gcloud scc notifications delete OLD_CONFIG_ID --organization=ORG_ID
```

## Message content

Each message shows the category, project, resource, severity, state and event time, with a button that opens the finding in the console.

- Security Health Analytics findings show the Explanation, Recommendation and exception instructions from `sourceProperties`.
- Threat detection findings show `description` and `nextSteps`.
- Sections without content are left out, and long sections are cut at Slack's 3000 character limit.

Edit [finding-detail.json](app/scc-finding-slack-notifications/block_templates/finding-detail.json) to change the layout. The available placeholders are listed in `PLACEHOLDER_KEYS` in `main.py`.

## Error handling and monitoring

- **Transient errors are retried.** These are network failures, HTTP 429 and 5xx responses, and Slack internal errors. Events older than `max_event_age_seconds`, default one hour, are dropped.
- **Permanent errors are logged and not retried.** These include an invalid token, an unknown channel, a bot not in the channel, invalid blocks and an undecodable message.

Create a log-based alert on this query to catch permanent failures:

```
resource.type="cloud_run_revision"
resource.labels.service_name="scc-slack-notifier"
severity>=ERROR
```

## Local development and tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r app/scc-finding-slack-notifications/requirements.txt pytest
pytest
```

Preview the Slack blocks for a sample notification. Add `--send` to post it, using `SLACK_BOT_TOKEN` and `SLACK_CHANNEL` from your environment:

```bash
cd app/scc-finding-slack-notifications
python main.py ../../tests/fixtures/etd_v2_malware_bad_ip.json
```

## End-to-end test

After deployment, publish a sample notification to the topic and check the channel:

```bash
gcloud pubsub topics publish scc-findingsnotifier-topic \
  --project=PROJECT_ID \
  --message="$(cat tests/fixtures/sha_private_google_access.json)"
```

Then check that the **View in Cloud Console** button opens the finding for a real finding in your organization.

## Rotating the Slack token

Encrypt the new token as in step 3, update `slack_bot_token_ciphertext` and run `terraform apply`. The function reads the `latest` secret version when an instance starts. Redeploy it, or wait for instances to recycle, to pick up the new token immediately.
