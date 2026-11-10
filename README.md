# aws-breach-alarms

[한국어](README.ko.md)

Near-zero-cost AWS breach alarms: CloudTrail → EventBridge → SNS email. No Lambda, no servers, under $1/month.

> Status: v0.1.0. Patterns are verified against the EventBridge API, and the stacks are running in production accounts.

Born from a real incident where an attacker stole EC2 instance-role credentials via SSRF (IMDSv1) and operated for four days without a single alert, even though every step was recorded in CloudTrail.

- Design: [docs/design.md](docs/design.md)
- Lessons learned (anonymized): [docs/lessons-learned.md](docs/lessons-learned.md)

## Rules (v0.1)

| ID | Slug | Detects |
|---|---|---|
| R1 | `role-denied` | AccessDenied for a monitored role (stolen instance credentials blocked by a deny-outside-VPC policy) |
| R2 | `role-offsite` | Monitored role used from a non-allowed source IP |
| R3 | `remote-exec` | SSM SendCommand / StartSession and ECS ExecuteCommand by untrusted principals |
| R4 | `iam-persistence` | New IAM users, access keys, login profiles, policy changes |
| R5 | `defense-evasion` | CloudTrail / GuardDuty / Config / flow-log / WAF-log tampering |
| R5b | `alarm-tamper` | Changes to these alarms (rules, targets, SNS topic or subscription) |
| R6 | `exfil-prep` | Snapshot or AMI sharing, S3 policy or public-access changes, KMS key deletion |
| R7 | `console-signin` | Root sign-in, failed sign-ins, IAM sign-in without MFA |
| R8 | `waf-spike` | Spike in blocks on a chosen WAF rule (CloudWatch alarm) |
| H1 | `delivery-failure` | The alarm pipeline itself failing to deliver |

Deploy as a Terraform module or a CloudFormation template. Both are built from one rule catalog. Alerts go out from one home region; other regions forward matched events to it.

## Quick start (Terraform)

```hcl
module "breach_alarms" {
  source = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"

  alert_emails            = ["security@example.com"]
  monitored_role_names    = ["app-server-role"]                       # R1/R2
  allowed_source_patterns = ["203.0.113.10", "10.*", "*.amazonaws.com", "AWS Internal"]  # your NAT IPs etc.
}
```

- Confirm the subscription email once.
- IAM events and root sign-ins are recorded in us-east-1 (and a few other regions). Add `mode = "forwarder"` modules there; see [examples/terraform/multi-region](examples/terraform/multi-region/main.tf).
- Recommended for R1: [examples/policies/deny-outside-vpc.json](examples/policies/).

### Using an existing SNS topic

Set `alert_topic_arn` (CloudFormation: `ExistingTopicArn`). The module never changes that topic's policy, so add this statement to it yourself:

```json
{
  "Sid": "AllowBreachAlarms",
  "Effect": "Allow",
  "Principal": { "Service": ["events.amazonaws.com", "cloudwatch.amazonaws.com"] },
  "Action": "sns:Publish",
  "Resource": "<topic ARN>",
  "Condition": { "StringEquals": { "aws:SourceAccount": "<account ID>" } }
}
```

## Quick start (CloudFormation)

Deploy [cloudformation/template.json](cloudformation/template.json):
- Once with `Mode=home` and `AlertEmail` in your main region.
- With `Mode=forwarder` and `HomeRegion` in the other regions (StackSets work too).

## Cost

About $0.2–0.5/month: EventBridge rules and AWS service events are free, SNS email is free up to 1,000/month, and each CloudWatch alarm costs $0.10. A CloudTrail trail must exist.

## How it is tested

- Every rule has events that must and must not match (`tests/events/`).
- They are judged offline by [aws/event-ruler](https://github.com/aws/event-ruler), the engine behind EventBridge. `make verify-aws` cross-checks them with the real `TestEventPattern` API.
- The Terraform module (planned offline) and the CloudFormation template must render exactly the same patterns and messages.

See [CONTRIBUTING.md](CONTRIBUTING.md). Alert handling: [docs/runbook.md](docs/runbook.md).

## License

MIT
