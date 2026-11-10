# Resources that only exist in forwarder regions: send matched events to the home region's default bus.

locals {
  forwarder_arn_parts = local.is_home ? null : split(":", aws_iam_role.forwarder[0].arn)
  home_bus_arn        = local.is_home ? null : "arn:${local.forwarder_arn_parts[1]}:events:${var.home_region}:${local.forwarder_arn_parts[4]}:event-bus/default"
}

resource "aws_iam_role" "forwarder" {
  count = local.is_home ? 0 : 1

  name = "${local.name_prefix}-forwarder-${data.aws_region.current.name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.home_region != null
      error_message = "home_region is required when mode = \"forwarder\"."
    }
  }
}

resource "aws_iam_role_policy" "forwarder" {
  count = local.is_home ? 0 : 1

  name = "put-events-to-home-bus"
  role = aws_iam_role.forwarder[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = local.home_bus_arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "forward" {
  for_each = { for slug, r in local.event_rules : slug => r if !local.is_home }

  rule      = aws_cloudwatch_event_rule.this[each.key].name
  target_id = "forward"
  arn       = local.home_bus_arn
  role_arn  = aws_iam_role.forwarder[0].arn
}

data "aws_region" "current" {}
