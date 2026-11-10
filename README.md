# aws-breach-alarms

[한국어](README.ko.md)

Near-zero-cost AWS breach alarms: CloudTrail → EventBridge → SNS email. No Lambda, no servers, under $1/month.

> Status: design phase (v0.1). Implementation has not started yet.

Born from a real incident where an attacker stole EC2 instance-role credentials via SSRF (IMDSv1) and operated for four days without a single alert, even though every step was recorded in CloudTrail.

- Design: [docs/design.md](docs/design.md)
- Lessons learned (anonymized): [docs/lessons-learned.md](docs/lessons-learned.md)

## Planned rules (v0.1)

| ID | Slug | Detects |
|---|---|---|
| R1 | `role-denied` | AccessDenied for a monitored role (stolen instance credentials blocked by a deny-outside-VPC policy) |
| R2 | `role-offsite` | Monitored role used from a non-allowed source IP |
| R3 | `remote-exec` | SSM SendCommand / StartSession and ECS ExecuteCommand by untrusted principals |
| R4 | `iam-persistence` | New IAM users, access keys, login profiles, policy changes |
| R5 | `defense-evasion` | CloudTrail / GuardDuty / Config / flow-log tampering, and tampering with these alarms |
| R6 | `exfil-prep` | Snapshot or AMI sharing, S3 policy or public-access changes, KMS key deletion |
| R7 | `console-signin` | Root sign-in, failed sign-ins, IAM sign-in without MFA |
| R8 | `waf-spike` | Spike in blocks on a chosen WAF rule (CloudWatch alarm) |
| H1 | `delivery-failure` | The alarm pipeline itself failing to deliver |

Deploy as a Terraform module or a CloudFormation template. Both are built from one rule catalog. Alerts go out from one home region; other regions forward matched events to it.

## License

MIT
