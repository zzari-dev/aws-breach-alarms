# Resources that only exist in the home region: the alert topic, its DLQ and alarms.

locals {
  create_topic = local.is_home && var.alert_topic_arn == null
  topic_arn    = local.is_home ? (local.create_topic ? aws_sns_topic.alerts[0].arn : var.alert_topic_arn) : null
  account_id   = local.is_home ? split(":", local.topic_arn)[4] : null
}

resource "aws_sns_topic" "alerts" {
  count = local.create_topic ? 1 : 0

  name              = "${local.name_prefix}-alerts"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_policy" "alerts" {
  count = local.create_topic ? 1 : 0

  arn = aws_sns_topic.alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeAndCloudWatch"
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "cloudwatch.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts[0].arn
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  for_each = local.create_topic ? toset(var.alert_emails) : toset([])

  topic_arn = local.topic_arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sqs_queue" "dlq" {
  count = local.is_home ? 1 : 0

  name                      = "${local.name_prefix}-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = var.kms_key_arn
  sqs_managed_sse_enabled   = var.kms_key_arn == null ? true : null
  tags                      = var.tags
}

resource "aws_sqs_queue_policy" "dlq" {
  count = local.is_home ? 1 : 0

  queue_url = aws_sqs_queue.dlq[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridge"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq[0].arn
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })
}

resource "aws_cloudwatch_event_target" "alert" {
  for_each = { for slug, r in local.event_rules : slug => r if local.is_home }

  rule      = aws_cloudwatch_event_rule.this[each.key].name
  target_id = "alert"
  arn       = local.topic_arn

  input_transformer {
    input_paths    = local.message.input_paths
    input_template = local.messages[each.key]
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq[0].arn
  }
}

resource "aws_cloudwatch_metric_alarm" "delivery_failure" {
  count = local.is_home ? 1 : 0

  alarm_name          = "${local.name_prefix}-h1-delivery-failure"
  alarm_description   = "[aws-breach-alarms] H1: an alert could not be delivered and is waiting in the dead-letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq[0].name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "waf_spike" {
  for_each = local.is_home ? { for a in var.waf_alarms : "${a.web_acl}/${a.rule}" => a } : {}

  alarm_name          = "${local.name_prefix}-r8-waf-spike-${replace(each.key, "/", "-")}"
  alarm_description   = "[aws-breach-alarms] R8: requests blocked by WAF rule ${each.value.rule} spiked."
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  dimensions          = { WebACL = each.value.web_acl, Rule = each.value.rule, Region = split(":", local.topic_arn)[3] }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [local.topic_arn]
  tags                = var.tags
}
