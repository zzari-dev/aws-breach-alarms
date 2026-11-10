# Changelog

## [Unreleased]

### Added
- Rule catalog v0.1: R1 role-denied, R2 role-offsite, R3 remote-exec, R4 iam-persistence, R5 defense-evasion, R5b alarm-tamper, R6 exfil-prep, R7 console-signin, R8 waf-spike, H1 delivery-failure.
- Terraform module (repository root) with `home` and `forwarder` modes.
- CloudFormation template generated from the same catalog.
- Pattern tests judged by aws/event-ruler; Terraform and CloudFormation parity tests.
- Runbook in English and Korean.
