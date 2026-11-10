output "sns_topic_arn" {
  description = "Home only: the alert topic. Subscribe more endpoints (e.g. AWS Chatbot) here."
  value       = local.is_home ? aws_sns_topic.alerts[0].arn : null
}

output "dlq_arn" {
  description = "Home only: dead-letter queue for alerts EventBridge could not deliver."
  value       = local.is_home ? aws_sqs_queue.dlq[0].arn : null
}

output "forwarder_role_arn" {
  description = "Forwarder only: role EventBridge uses to put events on the home bus."
  value       = local.is_home ? null : aws_iam_role.forwarder[0].arn
}

output "rule_arns" {
  description = "Created EventBridge rules by slug."
  value       = { for slug, r in aws_cloudwatch_event_rule.this : slug => r.arn }
}
