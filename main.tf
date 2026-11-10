locals {
  rules_dir = "${path.module}/rules"
  defaults  = jsondecode(file("${local.rules_dir}/defaults.json"))
  message   = jsondecode(file("${local.rules_dir}/message.json"))
  sentinel  = "__none__"

  catalog = { for f in fileset(local.rules_dir, "r*.json") :
    jsondecode(file("${local.rules_dir}/${f}")).slug => jsondecode(file("${local.rules_dir}/${f}"))
  }

  is_home     = var.mode == "home"
  name_prefix = coalesce(var.name_prefix, local.defaults.name_prefix)
  runbook_url = coalesce(var.runbook_url, local.defaults.runbook_url)
  operators   = var.operator_principal_patterns == null ? local.defaults.operator_principal_patterns : var.operator_principal_patterns

  # Each @@token@@ in a pattern becomes this JSON text. "" marks an empty value.
  encoded = {
    name_prefix                 = jsonencode(local.name_prefix)
    alert_topic_arn             = jsonencode(local.is_home ? local.topic_arn : local.sentinel)
    monitored_role_names        = length(var.monitored_role_names) > 0 ? jsonencode(var.monitored_role_names) : ""
    allowed_source_patterns     = length(var.allowed_source_patterns) > 0 ? jsonencode(var.allowed_source_patterns) : ""
    operator_principal_patterns = length(local.operators) > 0 ? jsonencode(local.operators) : ""
    deployer_principal_patterns = length(var.deployer_principal_patterns) > 0 ? jsonencode(var.deployer_principal_patterns) : ""
  }

  # Known at plan time (unlike the topic ARN), so rule keys never depend on apply results.
  has_value = {
    name_prefix                 = true
    alert_topic_arn             = true
    monitored_role_names        = length(var.monitored_role_names) > 0
    allowed_source_patterns     = length(var.allowed_source_patterns) > 0
    operator_principal_patterns = length(local.operators) > 0
    deployer_principal_patterns = length(var.deployer_principal_patterns) > 0
  }

  event_rules = { for slug, r in local.catalog : slug => r
    if r.kind == "event"
    && (var.enabled_rules == null || contains(coalesce(var.enabled_rules, []), slug))
    && alltrue([for p, need in lookup(r, "params", {}) : need != "required" || local.has_value[p]])
  }

  patterns = { for slug, r in local.event_rules : slug => replace(replace(replace(replace(replace(replace(
    jsonencode(r.pattern),
    "\"@@name_prefix@@\"", local.encoded.name_prefix),
    "\"@@alert_topic_arn@@\"", local.encoded.alert_topic_arn),
    "\"@@monitored_role_names@@\"", local.encoded.monitored_role_names),
    "\"@@allowed_source_patterns@@\"", local.encoded.allowed_source_patterns),
    "\"@@operator_principal_patterns@@\"", coalesce(local.encoded.operator_principal_patterns, jsonencode([local.sentinel]))),
    "\"@@deployer_principal_patterns@@\"", coalesce(local.encoded.deployer_principal_patterns, jsonencode([local.sentinel])))
  }

  # Each line is its own quoted string: EventBridge reads InputTemplate as JSON.
  messages = { for slug, r in local.event_rules : slug => join("\n", [for line in local.message.template :
    format("\"%s\"", replace(replace(replace(replace(replace(replace(replace(replace(line,
      "{severity}", r.severity), "{id}", r.id), "{slug}", r.slug), "{title}", r.title), "{why}", r.why),
    "{runbook_url}", local.runbook_url), "{anchor}", "${lower(r.id)}-${r.slug}"), "\"", "\\\""))
  ]) }
}

resource "aws_cloudwatch_event_rule" "this" {
  for_each = local.event_rules

  name          = "${local.name_prefix}-${lower(each.value.id)}-${each.key}"
  description   = "[aws-breach-alarms] ${each.value.id}: ${each.value.title}"
  state         = each.value.state
  event_pattern = local.patterns[each.key]
  tags          = var.tags
}
