variable "mode" {
  description = "home: creates the SNS topic and sends alerts (deploy once). forwarder: forwards matched events to the home region."
  type        = string
  default     = "home"

  validation {
    condition     = contains(["home", "forwarder"], var.mode)
    error_message = "mode must be \"home\" or \"forwarder\"."
  }
}

variable "home_region" {
  description = "Forwarder only: region of the home deployment."
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Prefix for resource names. R5b watches EventBridge rules with this prefix."
  type        = string
  default     = null
}

variable "alert_emails" {
  description = "Home only: email addresses that receive alerts. Each must confirm the SNS subscription once."
  type        = list(string)
  default     = []
}

variable "enabled_rules" {
  description = "Rule slugs to create (see rules/). null creates every rule whose required settings are present."
  type        = list(string)
  default     = null
}

variable "monitored_role_names" {
  description = "R1/R2: IAM role names to watch, e.g. EC2 instance or ECS task roles. Empty skips R1/R2."
  type        = list(string)
  default     = []
}

variable "allowed_source_patterns" {
  description = "R2: source IP wildcards where monitored roles may be used, e.g. [\"203.0.113.10\", \"10.*\", \"*.amazonaws.com\", \"AWS Internal\"]. Empty skips R2."
  type        = list(string)
  default     = []
}

variable "operator_principal_patterns" {
  description = "R3: principal ARN wildcards allowed to run SSM commands, sessions and ECS Exec. null uses SSO roles and SSM State Manager."
  type        = list(string)
  default     = null
}

variable "deployer_principal_patterns" {
  description = "R4/R6: principal ARN wildcards (CI, Terraform) whose IAM, sharing and bucket-policy changes are expected."
  type        = list(string)
  default     = []
}

variable "runbook_url" {
  description = "Base URL of the runbook linked from alerts. null uses the project's runbook."
  type        = string
  default     = null
}

variable "waf_alarms" {
  description = "Home only, R8: one CloudWatch alarm per entry on AWS/WAFV2 BlockedRequests."
  type = list(object({
    web_acl   = string
    rule      = string
    threshold = optional(number, 10)
  }))
  default = []
}

variable "kms_key_arn" {
  description = "Optional KMS key for the SNS topic and DLQ. Its key policy must allow events.amazonaws.com and cloudwatch.amazonaws.com."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

variable "alert_topic_arn" {
  description = "Home only: send alerts to this existing SNS topic instead of creating one. The module does not change its policy: allow events.amazonaws.com and cloudwatch.amazonaws.com to sns:Publish yourself (see README)."
  type        = string
  default     = null
}
