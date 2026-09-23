output "function_name" {
  value = google_cloudfunctions2_function.cf.name
}

output "pubsub_topic" {
  value = google_pubsub_topic.sccfindings.id
}

output "notification_config" {
  value = google_scc_v2_organization_notification_config.slack.name
}

output "runtime_service_account" {
  value = google_service_account.sccnotifier.email
}
