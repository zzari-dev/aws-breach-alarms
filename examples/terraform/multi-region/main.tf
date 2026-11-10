# Alerts are sent from one home region. Other regions forward matched events to it:
# - us-east-1: IAM, STS global endpoint, console sign-in
# - us-east-2, us-west-2: root console sign-in can be recorded here
# - eu-north-1, ap-southeast-2: IAM user console sign-in can be recorded here
# Add every other region that runs workloads the same way.

locals {
  home_region = "ap-northeast-2"
  forwarder = {
    mode                        = "forwarder"
    home_region                 = local.home_region
    monitored_role_names        = ["app-server-role"]
    allowed_source_patterns     = ["203.0.113.10", "10.*", "*.amazonaws.com", "AWS Internal"]
    deployer_principal_patterns = ["arn:aws:sts::*:assumed-role/terraform-deployer/*"]
  }
}

provider "aws" {
  region = local.home_region
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_east_2"
  region = "us-east-2"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu_north_1"
  region = "eu-north-1"
}

provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
}

module "home" {
  source = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"

  alert_emails                = ["security@example.com"]
  monitored_role_names        = local.forwarder.monitored_role_names
  allowed_source_patterns     = local.forwarder.allowed_source_patterns
  deployer_principal_patterns = local.forwarder.deployer_principal_patterns
}

module "us_east_1" {
  source    = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"
  providers = { aws = aws.us_east_1 }

  mode                        = local.forwarder.mode
  home_region                 = local.forwarder.home_region
  monitored_role_names        = local.forwarder.monitored_role_names
  allowed_source_patterns     = local.forwarder.allowed_source_patterns
  deployer_principal_patterns = local.forwarder.deployer_principal_patterns
}

module "us_east_2" {
  source    = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"
  providers = { aws = aws.us_east_2 }

  mode          = local.forwarder.mode
  home_region   = local.forwarder.home_region
  enabled_rules = ["console-signin", "alarm-tamper"]
}

module "us_west_2" {
  source    = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"
  providers = { aws = aws.us_west_2 }

  mode          = local.forwarder.mode
  home_region   = local.forwarder.home_region
  enabled_rules = ["console-signin", "alarm-tamper"]
}

module "eu_north_1" {
  source    = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"
  providers = { aws = aws.eu_north_1 }

  mode          = local.forwarder.mode
  home_region   = local.forwarder.home_region
  enabled_rules = ["console-signin", "alarm-tamper"]
}

module "ap_southeast_2" {
  source    = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"
  providers = { aws = aws.ap_southeast_2 }

  mode          = local.forwarder.mode
  home_region   = local.forwarder.home_region
  enabled_rules = ["console-signin", "alarm-tamper"]
}
