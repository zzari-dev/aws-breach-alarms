# Lessons Learned from a Real Breach

- Korean: [lessons-learned.ko.md](lessons-learned.ko.md)
- Design: [design.md](design.md)

This is the incident that led to this project. Company names, service names, domains, IPs, and account IDs have been removed. Dates are relative to the attacker's first access (Day 0).

## 1. Environment

- A B2B SaaS service in a single AWS account
- A PHP web application on EC2, plus some container services on ECS Fargate
- Aurora MySQL as the database
- AWS WAF in front of a public ALB
- Every EC2 instance shared one IAM role, which was effectively an administrator

## 2. Attack chain

| Stage | When | What happened |
|---|---|---|
| Recon | Day 0 | Mass enumeration of web endpoints. Endpoints without authorization checks (IDOR) returned other customers' payroll data and account details |
| File read | Day 0 | Path traversal in a download feature (LFI) exposed configuration files and source code, including DB credentials and the application encryption key |
| SSRF | Day 0 | A **test endpoint left in production** sent HTTP requests to a user-supplied URL. The HTTP client had a `base_uri`, but an absolute URL overrides it |
| Credential theft | Day 0 | The SSRF called the instance metadata service (IMDSv1, `169.254.169.254`) and returned the EC2 role's temporary credentials |
| Lateral movement | Day 0–3 | The stolen credentials were used from 10+ external IPs. About 190 SSM `SendCommand` calls and about 20 ECS `ExecuteCommand` sessions ran commands on every server |
| Exfiltration | Day 0–3 | Database dumps were uploaded to a temporary S3 prefix, downloaded, then deleted. They contained the full customer table, card data, digital certificates with private keys, and bank accounts with balances |
| Extortion | Day 4 | A ransom email arrived. **This was how the company learned of the breach** |

## 3. Root causes and lessons

### 3.1 Test code in production
- A test controller was deployed to production and reachable without authentication.
- **Lesson**: strip test and debug routes at build time. Also block paths such as `/test`, `/debug`, and `/webhook` in WAF by default.

### 3.2 IMDSv1
- An old AWS SDK did not support IMDSv2, so IMDSv1 stayed enabled.
- IMDSv2 requires fetching a session token first, so a plain SSRF cannot get credentials.
- **Lesson**: require IMDSv2 (`HttpTokens=required`) with a hop limit of 1. Any SDK that blocks this is the first thing to upgrade.

### 3.3 Over-privileged role with no location restriction
- One compromised web server meant a compromised account: the single role could use SSM, ECS, S3, and Secrets Manager.
- Nothing stopped the stolen credentials from being used outside the company network.
- **Lessons**:
  - Give each workload its own least-privilege role.
  - Add a deny statement using `aws:SourceVpc`, `aws:SourceIp` (NAT IPs), and `aws:ViaAWSService` so the role **cannot be used outside the VPC**.
  - During the response, external use stopped the moment this deny policy was attached.
  - Remove remote execution (`ssm:SendCommand`, `ssm:StartSession`, `ecs:ExecuteCommand`) from server roles.

### 3.4 Missing authorization checks (IDOR)
- Any logged-in user could read another company's data by changing the company ID in the URL.
- **Lesson**: every data-access endpoint must check on the server that the caller owns the resource. A WAF cannot fix this.

### 3.5 How sensitive data was stored
- Card data sat **in plaintext in an integration log table**, even though the main table was encrypted.
- Application encryption used a static IV, and the key lived on the same servers as the code, so it was stolen with everything else.
- **Lessons**:
  - Redact sensitive fields from debug and integration logs.
  - Keep encryption keys in KMS, with separate principals allowed to use them.
  - "It was encrypted" means nothing if the key leaks with the data.

### 3.6 The detection gap — why this project exists
- The attack ran for four days and **not one alarm fired.**
  - GuardDuty was suspended to save money. Secrets Manager was called millions of times a day, which inflated CloudTrail volume and therefore GuardDuty's price.
  - WAF logging had silently stopped long before.
  - There were no alarms on IAM changes, remote command execution, or role use from outside IPs.
- CloudTrail recorded every step. **The data was there; nobody was watching.**
- **Lesson**: even without paid detection, CloudTrail → EventBridge → SNS delivers the key signals **almost for free**. Signals from this incident:

| Signal in this incident | Rule |
|---|---|
| First call with stolen server credentials from an outside IP (`GetCallerIdentity`) | R2 `role-offsite` |
| External use after the deny policy was attached → AccessDenied | R1 `role-denied` |
| SSM commands and ECS Exec using the server role | R3 `remote-exec` |
| IAM reads and change attempts | R4 `iam-persistence` (changes only) |
| Logging and detection services were off | R5 `defense-evasion` (fires when they are switched off) |
| Dumps uploaded to a temporary S3 prefix and deleted | Data events, out of scope for v0.1. The aim is to catch R2/R3 earlier |
| Retries against blocked vulnerable paths | R8 `waf-spike` |

### 3.7 What helped
- **S3 versioning**: the dumps the attacker deleted survived as noncurrent versions, which made it possible to confirm exactly what leaked.
- **ALB access logs**: attacker IPs, paths, and timing could be reconstructed to the second.
- **Database-backed sessions**: matching attack request times to session creation times identified the web accounts the attacker used.
- **Multi-region CloudTrail trail**: the `ec2RoleDelivery` field confirmed the credentials came through IMDSv1.

## 4. Lessons from the response itself

1. **Keep an inventory of your own IPs.** The office IP doing legitimate bulk queries was mistaken for the attacker and blocked for about two hours.
2. **Check the blast radius before revoking sessions or rotating credentials.** Revoking a role's sessions also cuts off healthy servers' temporary credentials.
3. **Never print personal data while analyzing.** Look at formats and counts only. Keep evidence in a separate, access-controlled store.
4. **Confirm the "read replica" actually exists.** After a reader instance is deleted, the reader endpoint points to the writer, and heavy analysis queries run on production.
5. **Preserve evidence first, clean up later.** Take EBS snapshots before deleting attacker files on servers.
6. **Report the leak as "the confirmed minimum".** Some channels leave no record, such as SSM command output and interactive sessions.
