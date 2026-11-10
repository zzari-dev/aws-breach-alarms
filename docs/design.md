# aws-breach-alarms — Design

- Status: In review (v0.1)
- License: MIT
- Korean: [design.ko.md](design.ko.md)
- Background: [Lessons learned](lessons-learned.md)

## 1. Problem

Detection services (GuardDuty, Security Hub, SIEMs) cost money. Small teams switch them off to save it. What remains is a state where **CloudTrail records everything and nobody looks at it**. In the incident behind this project, the attacker operated for four days without a single alert. The team found out only when a ransom email arrived.

## 2. Goals and non-goals

### Goals
- Alert by email within 1–2 minutes on the few CloudTrail management events that **strongly indicate a breach**.
- Cost **under $1/month**. No Lambda, no servers.
- Ship as a Terraform module and a CloudFormation template, both built from one rule catalog.
- Make the module reusable in any account by changing configuration only.
- Make it noticeable when the alarm pipeline itself is disabled or broken.

### Non-goals (v0.1)
- Replacing GuardDuty: no ML anomaly detection, no threat intelligence.
- Application-logic attacks (IDOR, SQL injection): they never reach CloudTrail.
- S3/Lambda **data events**: they carry extra CloudTrail charges.
- Automated response (blocking, quarantine): alert only.
- Multi-account aggregation (AWS Organizations): on the roadmap.

## 3. Alternatives considered

| Option | Monthly cost | Why not chosen |
|---|---|---|
| GuardDuty | Scales with CloudTrail volume (tens to hundreds of USD for noisy accounts) | Often switched off for cost. Recommended alongside this project, not instead of it |
| CloudTrail → CloudWatch Logs + metric filters | ~$0.76 per GB ingested | Ingestion cost grows with event volume |
| Lambda polling `LookupEvents` | Cents | API limited to 2 requests/s, so high-volume accounts can't be fully scanned, and detection lags |
| AWS User Notifications | Free | Console-centric. Hard to manage a rule set as code |
| **EventBridge rules → SNS (chosen)** | **~0** | Limited pattern expressiveness (§9) |

## 4. Architecture

```
             [home region]
CloudTrail ─▶ EventBridge default bus ─▶ rules R1–R7 ─▶ input transformer ─▶ SNS ─▶ email
                    ▲                                                        ▲     └▶ (opt) Slack
                    │ cross-region PutEvents                                 │
             [forwarder regions]                                             │
CloudTrail ─▶ default bus ─▶ forwarding rules (R4, R7, …) ─┘   WAF metric ─▶ CloudWatch alarm R8
                                                        EventBridge failures ─▶ alarm H1
```

### 4.1 Components
- **EventBridge default bus**: CloudTrail events are delivered only to the default bus. An active CloudTrail trail is required.
- **Rule state**:
  - Rules that only need write events use the default `ENABLED`.
  - Rules that must also see read-only calls (Get/List/Describe), namely R1 and R2, use **`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`**. CloudFormation supports this state, and so does Terraform through the `state` argument.
- **Input transformer**: turns event JSON into a readable email body (§6).
- **SNS topic**: holds the email subscribers. The topic policy allows publishing only from `events.amazonaws.com` and `cloudwatch.amazonaws.com`, with an `aws:SourceAccount` condition.
- **DLQ (SQS)**: keeps events that EventBridge failed to deliver to SNS.

### 4.2 Regions: home and forwarders
A CloudTrail event reaches only the bus **in the region where it was recorded**. That region depends on the event:

| Event | Recorded in |
|---|---|
| IAM, STS global endpoint | us-east-1 |
| Root console sign-in | One of us-east-1, us-east-2, us-west-2 |
| IAM user console sign-in (global endpoint) | us-east-1, or one of us-east-2, eu-north-1, ap-southeast-2 |
| IAM user console sign-in (regional endpoint) | That endpoint's region |
| Workload API calls | The workload's region |

- One SNS topic per region would mean many subscription confirmations and many things to manage.
- So **alerts are sent from a single home region**. Other regions run forwarding rules only, sending matched events to the home region's default bus as a cross-region event bus target.
- The module has `mode = "home" | "forwarder"`.
- When forwarding read-only events, **both** the forwarding rule and the home rule must use `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` (per AWS docs).
- **Recommended deployment**: the home region, plus us-east-1, us-east-2, us-west-2, eu-north-1, ap-southeast-2, plus every region that runs workloads.

## 5. Rule catalog

Each rule lives in one file, `rules/<id>.json`, containing:
- ID and slug
- Title and severity
- Description and runbook text
- Rule state (`ENABLED` or `ALL`)
- Region scope (`home`, `global`, `signin`, `any`)
- Event pattern template, where `${...}` placeholders are filled from configuration at deploy time

| ID | Slug | Severity | State | Detects |
|---|---|---|---|---|
| R1 | `role-denied` | High | ALL | Access denied for a monitored role |
| R2 | `role-offsite` | High | ALL | Monitored role used from a non-allowed source |
| R3 | `remote-exec` | High | ENABLED | Remote command execution by a non-trusted principal |
| R4 | `iam-persistence` | High | ENABLED | IAM backdoors |
| R5 | `defense-evasion` | High | ENABLED | Disabling logging, detection, or these alarms |
| R6 | `exfil-prep` | High | ENABLED | Preparing to share data externally |
| R7 | `console-signin` | High/Medium | ENABLED | Root sign-in, failed sign-in, sign-in without MFA |
| R8 | `waf-spike` | Medium | (metric alarm) | Spike in blocks on a chosen WAF rule |
| H1 | `delivery-failure` | High | (metric alarm) | Alert delivery failures |

### R1 `role-denied`: access denied for a monitored role
- **Match**: a session of a monitored role whose `errorCode` is one of `AccessDenied`, `AccessDeniedException`, `Client.UnauthorizedOperation`, `UnauthorizedOperation`.
- **Why**: healthy server code rarely hits authorization errors. With a "deny outside the VPC" policy on the role, stolen credentials used elsewhere *always* produce a denial. This rule turns that denial into an alert.
- **Recommended prerequisite**: `examples/policies/deny-outside-vpc.json`
  ```json
  {
    "source": [{ "prefix": "aws." }],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "userIdentity": { "arn": [{ "wildcard": "arn:aws:sts::${account_id}:assumed-role/${role_name}/*" }] },
      "errorCode": ["AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation", "UnauthorizedOperation"]
    }
  }
  ```
- Each monitored role adds one `arn` value (OR).

### R2 `role-offsite`: monitored role used from a non-allowed source
- **Match**: a session of a monitored role whose `sourceIPAddress` matches none of the allowed patterns.
- **Allowed pattern examples**: NAT public IPs, private IPs seen through VPC endpoints (`10.*`), AWS services calling on your behalf (`*.amazonaws.com`), `AWS Internal`.
  ```json
  "sourceIPAddress": [{ "anything-but": { "wildcard": ${allowed_source_patterns} } }]
  ```
- **Why**: in the real incident, the attacker's first move was calling `GetCallerIdentity` with the stolen credentials from an outside IP. Unlike R1, this rule works **without** a deny policy.
- **Caveats**:
  - Wildcards can only widen by whole octets (`10.*`). Negated CIDR (`anything-but` + `cidr`) is not supported.
  - Every read-only event of the account is evaluated against this pattern, but only matches go to SNS.
- R2 is not created if `allowed_source_patterns` is empty.

### R3 `remote-exec`: remote command execution
- **Match**: `ssm:SendCommand`, `ssm:StartSession`, `ssm:ResumeSession`, or `ecs:ExecuteCommand` called by a non-trusted principal.
  ```json
  "userIdentity": { "arn": [{ "anything-but": { "wildcard": ${trusted_principal_patterns} } }] }
  ```
- **Default trusted principals**: `arn:aws:sts::${account_id}:assumed-role/AWSReservedSSO_*`, `arn:aws:sts::${account_id}:assumed-role/AWSServiceRoleForAmazonSSM/*`.
- **Why**: in the real incident, the attacker ran about 190 SSM commands and about 20 ECS Exec sessions with the stolen server role.
- **To verify**: how `anything-but` treats events without `userIdentity.arn` (`type: AWSService`). Tests will settle it.

### R4 `iam-persistence`: IAM backdoors (us-east-1)
- **Match**: any of the following (`eventSource: iam.amazonaws.com`) called by a non-trusted principal:
  - `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`
  - `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, `AttachGroupPolicy`, `PutGroupPolicy`
  - `CreateRole`, `UpdateAssumeRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `AddUserToGroup`
  - `DeactivateMFADevice`, `DeleteVirtualMFADevice`
  - `CreateOpenIDConnectProvider`, `CreateSAMLProvider`
- **Trusted principals**: add deployment pipelines (Terraform/CI roles) to reduce noise. The default is empty, so every change alerts.

### R5 `defense-evasion`: disabling logging, detection, or these alarms
- **Match**: any of the following:
  - CloudTrail: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`
  - GuardDuty: `DeleteDetector`, `UpdateDetector`, `DisassociateFromMasterAccount`
  - Config: `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`
  - VPC and WAF logs: `DeleteFlowLogs`, `DeleteLoggingConfiguration`
  - Security Hub: `DisableSecurityHub`
  - **Self-protection**:
    - `events:DeleteRule`, `DisableRule`, `RemoveTargets`, `PutRule`, `PutTargets` on rules named `${name_prefix}*`
    - `sns:DeleteTopic`, `Unsubscribe`, `SetTopicAttributes`, `RemovePermission` on our topic
- **Limitation**: the rule being deleted may not process its own deletion event. Self-protection therefore lives in a separate rule (`R5b`), so an attacker has to remove more than one rule at once.

### R6 `exfil-prep`: preparing to share data externally
- **Match**: any of the following:
  - Snapshot and image sharing: EC2 `ModifySnapshotAttribute`, `ModifyImageAttribute`; RDS `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute`
  - S3 exposure: `PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`, `DeletePublicAccessBlock`, `PutAccountPublicAccessBlock` (s3control)
  - KMS: `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`
- **v0.2**: narrow snapshot sharing to "external account added" only.

### R7 `console-signin`: console sign-in (sign-in regions)
- `detail-type: "AWS Console Sign In via CloudTrail"`, `eventName: ConsoleLogin`
  - **R7a root sign-in** (High): `userIdentity.type = Root`. Alerts on both success and failure.
  - **R7b failed sign-in** (Medium): `responseElements.ConsoleLogin = Failure`.
  - **R7c sign-in without MFA** (Medium): `additionalEventData.MFAUsed = No` with `userIdentity.type = IAMUser`.
    - Federated (SSO) sign-ins are excluded, because MFA happens at the IdP and they always log `No`.

### R8 `waf-spike`: WAF block spike (optional)
- **Match**: the sum of `AWS/WAFV2 BlockedRequests` (dimensions WebACL, Rule, Region) is at least `threshold` over 5 minutes.
- **Why**: hits on a "vulnerable paths" block rule mean someone is trying again.
- Each `waf_alarms` entry creates one CloudWatch alarm ($0.10/month).

### H1 `delivery-failure`: watching the pipeline itself
- **Match**: `AWS/Events FailedInvocations` for our rules > 0, or DLQ `ApproximateNumberOfMessagesVisible` > 0.
- **Why**: catches the case where detection worked but the alert never arrived.

## 6. Alert message

EventBridge cannot set the SNS email subject (it defaults to "AWS Notification Message"). The **first line of the body acts as the subject**.

```
[aws-breach-alarms] HIGH R3 remote-exec
What : ssm.amazonaws.com SendCommand
Who  : arn:aws:sts::123456789012:assumed-role/app-server-role/i-0abc...
From : 198.51.100.7 (us-east-1)
When : 2026-01-01T12:34:56Z
Error: -
Event: 3f2a...-eventID
Why it matters: Remote command execution by a non-trusted principal. ...
Runbook: https://github.com/<org>/aws-breach-alarms/blob/main/docs/runbook.md#r3
```

- Title, severity, "Why it matters", and the runbook link are static strings from rule metadata.
- The other fields come from `InputPathsMap` (`$.detail.eventName`, …).
- Missing paths render empty.

## 7. Configuration

| Name | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"home"` | `home` creates SNS and alarms. `forwarder` only forwards to the home region |
| `home_region` | string | — | Where forwarders send events |
| `name_prefix` | string | `"breach-alarms"` | Resource name prefix. Also used by R5 self-protection |
| `alert_emails` | list(string) | `[]` | Home only. Each address must confirm the subscription once |
| `enabled_rules` | list(string) | Default set for the region's role | Rule IDs to create |
| `monitored_role_names` | list(string) | `[]` | Roles for R1/R2. If empty, R1/R2 are skipped |
| `allowed_source_patterns` | list(string) | `[]` | R2 allowed-source wildcards |
| `trusted_principal_patterns` | list(string) | SSO and SSM service roles | Principals excluded from R3/R4 |
| `waf_alarms` | list(object) | `[]` | R8: `{ web_acl, rule, region, threshold }` |
| `kms_key_arn` | string | `null` | Optional key for SNS/SQS encryption |
| `tags` | map(string) | `{}` | Common tags |

**Outputs**: `sns_topic_arn`, `rule_arns`, `dlq_arn`, `forwarder_role_arn`.

**CloudFormation**:
- Uses the same parameters. Lists are `CommaDelimitedList`.
- Conditions such as `Mode` and `EnableR1` switch resources on and off.
- For multiple regions, use StackSets or one stack per region.

## 8. Noise and tuning

| Rule | Expected rate (small account) | False-positive source | Tuning |
|---|---|---|---|
| R1 | ~0 | Missing permission after a deploy | Fix the permission. It's a real signal |
| R2 | ~0 | NAT IP change, new VPC endpoint | Update `allowed_source_patterns` |
| R3 | When operators work | Operators not using SSO | Add the operator principal to trusted |
| R4 | On infra deploys | Terraform/CI roles | Add deployer roles to trusted |
| R5 | Very rare | Updating this module | Alerts during your own deploy are expected |
| R6 | Rare | Legitimate bucket policy changes | v0.2 narrowing |
| R7 | Password typos | Failed sign-in | Disable R7b |

## 9. Known limitations

- **Pattern matching only**: no thresholds over time (for example "10 times in 5 minutes") and no correlation.
- **No negated CIDR**: R2 allowed sources are octet-level wildcards.
- **CloudTrail delay**: events usually reach the bus within a few minutes.
- **No data events**: S3 object reads and deletes are not detected.
- **Pattern size**: 2,048 characters by default, up to 4,096 with a quota increase. Long allow-lists need to be split across rules.
- **An attacker deleting the alarms**: R5b reports it, but the same permissions can also delete the SNS subscription. The real fix is account separation (Organizations with a delegated administrator), which is on the roadmap.

## 10. Repository layout

```
aws-breach-alarms/
├─ rules/                     # Source of truth: rule metadata + pattern templates
├─ terraform/                 # Module (reads rules/*.json via file() + jsondecode())
│  └─ examples/{single-region,multi-region}/
├─ cloudformation/template.yaml        # Generated by scripts/build_cfn.py — do not edit
├─ scripts/build_cfn.py
├─ examples/policies/deny-outside-vpc.json
├─ tests/
│  ├─ events/<rule>/{match,nomatch}/*.json   # Anonymized CloudTrail events
│  └─ ...
├─ docs/
│  ├─ design.md, design.ko.md
│  ├─ lessons-learned.md, lessons-learned.ko.md
│  └─ runbook.md          # Per-rule response guide
├─ README.md, README.ko.md, LICENSE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
└─ .github/workflows/ci.yml
```

## 11. Testing strategy (TDD)

1. **Pattern tests (core)**: every rule has events that must match and events that must not. A failing test comes before every pattern change.
   - **Engine**: CI runs [`aws/event-ruler`](https://github.com/aws/event-ruler), the open-source matching library behind EventBridge. The goal is the same verdicts, offline, without credentials.
   - **Cross-check**: maintainers run the same fixtures through `aws events test-event-pattern` (`make verify-aws`) to confirm parity. This needs credentials but is free and creates no resources.
   - **Fixtures**: shaped like the real incident's events, with account IDs and IPs replaced by documentation values.
2. **Generated-artifact test**: CI regenerates the CloudFormation template with `build_cfn.py` and fails if it differs from the committed `template.yaml`.
3. **Static checks**: `terraform fmt -check`, `terraform validate`, `terraform test` (mock provider), `cfn-lint`, `gitleaks`.
4. **Deployment check (before each release, test account)**:
   - Trigger every rule safely and confirm an email arrives (for R4, create and delete a temporary IAM user).
   - Confirm cross-region forwarding in forwarder mode.

## 12. Cost (monthly, small account)

| Item | Cost |
|---|---|
| EventBridge rules, receiving AWS service events | 0 (AWS service events are free) |
| Cross-region forwarding | ~$1 per million matched events → effectively 0 |
| Input transformer | 0 |
| SNS email (first 1,000) | 0 |
| SQS DLQ | 0 (free tier) |
| CloudWatch alarms (each R8 alarm, H1) | ~$0.10 each |
| **Total** | **~$0.2–0.5** |

- Whether read-only event delivery (`ALL` state) is also free will be confirmed on a test account bill before release. The public docs don't mention a separate charge.
- Without a CloudTrail trail you need one. The first copy of management events is free; you pay only for S3 storage.

## 13. Security and publishing rules

- No account IDs, IPs, domains, company/service names, or real role names in the repository.
- Fixtures use documentation account IDs (`123456789012`, `111122223333`) and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) only.
- CI runs `gitleaks`, and a human reviews before publishing.
- The only IAM permission created is `events:PutEvents` for the forwarder role, scoped to the home bus.
- `SECURITY.md` describes how to report vulnerabilities.

## 14. Versioning and contributing

- SemVer. Adding a rule is a minor release. Narrowing a pattern or renaming a rule is a major release, because alerts may disappear.
- A new rule must include all of the following (`CONTRIBUTING.md`):
  - `rules/<id>.json`
  - match/nomatch fixtures
  - A runbook entry
  - A CHANGELOG entry

## 15. Decision log

| # | Decision | Reason |
|---|---|---|
| D1 | No Lambda | Zero cost and zero ops keep it switched on |
| D2 | Rules as JSON | Terraform reads them directly. CloudFormation is generated from them |
| D3 | Alerts from a single home region | One subscription and one place to manage |
| D4 | event-ruler for pattern tests | Same verdicts as the real engine, without credentials |
| D5 | Separate R1 and R2 | Works both for teams with a deny policy and teams without one |

## 16. Roadmap

- **v0.1**: R1–R8, H1, Terraform and CloudFormation, home/forwarder modes, email
- **v0.2**:
  - Slack through AWS Chatbot
  - Narrower snapshot and S3 filters
  - Security groups opened to `0.0.0.0/0`
  - Activity in unused regions
- **v0.3**:
  - Multi-account through AWS Organizations, aggregated in a delegated administrator account
  - (Optional, small cost) ALB log scanning Lambda and alert enrichment Lambda
