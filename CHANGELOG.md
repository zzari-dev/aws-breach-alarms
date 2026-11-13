# Changelog

## [Unreleased]

### Added
- An empty `runbook_url` / `RunbookUrl` omits the runbook line from alerts (for teams that keep the runbook internally).

### Changed
- `cloudformation/template.json` is written with one-space indentation so it stays under the 51,200-byte limit for `aws cloudformation deploy` without `--s3-bucket`.

## [0.1.0] - 2026-11-11

### Added
- Rule catalog v0.1: R1 role-denied, R2 role-offsite, R3 remote-exec, R4 iam-persistence, R5 defense-evasion, R5b alarm-tamper, R6 exfil-prep, R7 console-signin, R8 waf-spike, H1 delivery-failure.
- Terraform module (repository root) with `home` and `forwarder` modes.
- CloudFormation template generated from the same catalog.
- Pattern tests judged by aws/event-ruler; Terraform and CloudFormation parity tests.
- Runbook in English and Korean.
- `alert_topic_arn` / `ExistingTopicArn`: send alerts to an existing SNS topic instead of creating one.

### Verified
- Deployed to two real accounts across six regions. An IAM change in us-east-1 reached email through the home region in under 15 seconds.
- Alert messages are one quoted string per line, as EventBridge requires for multi-line text.
