# Smallest setup: one region, email alerts, watching the EC2 instance role.
# Root sign-in and IAM events are recorded in us-east-1; see ../multi-region to catch them too.

provider "aws" {
  region = "ap-northeast-2"
}

module "breach_alarms" {
  source = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"

  alert_emails         = ["security@example.com"]
  monitored_role_names = ["app-server-role"]

  # Where the role is expected to call AWS from: NAT gateway IPs, VPC endpoints, AWS services.
  allowed_source_patterns = ["203.0.113.10", "10.*", "*.amazonaws.com", "AWS Internal"]

  # Your CI/Terraform role, so routine IAM and bucket-policy changes don't alert.
  deployer_principal_patterns = ["arn:aws:sts::*:assumed-role/terraform-deployer/*"]

  waf_alarms = [{ web_acl = "app-web-acl", rule = "block-vulnerable-paths", threshold = 10 }]
}
