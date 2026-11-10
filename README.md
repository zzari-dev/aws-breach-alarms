# aws-breach-alarms

Near-zero-cost AWS breach alarms: CloudTrail → EventBridge → SNS email. No Lambda, no servers, under $1/month.

> Status: design phase (v0.1). Implementation is in progress.

Born from a real incident where an attacker stole EC2 instance-role credentials via SSRF (IMDSv1) and operated for four days without a single alert, even though every step was recorded in CloudTrail.

- Design (Korean): [docs/design.md](docs/design.md)
- Lessons learned (Korean, anonymized): [docs/lessons-learned.md](docs/lessons-learned.md)

## Planned rules (v0.1)

| ID | Detects |
|---|---|
| R1 | AccessDenied from a monitored role (stolen instance credentials used outside the VPC) |
| R2 | SSM SendCommand / StartSession and ECS ExecuteCommand by untrusted principals |
| R3 | IAM persistence: new users, access keys, policy changes (us-east-1) |
| R4 | Defense evasion & exfil prep: CloudTrail stop, GuardDuty delete, snapshot sharing, S3 policy changes |
| R5 | Root console sign-in, failed console sign-ins (us-east-1) |
| R6 | WAF blocked-request spike on a chosen rule (CloudWatch alarm) |

Deployable as a Terraform module or a CloudFormation template, both generated from one rule catalog.

## License

MIT
