# Runbook

[한국어](runbook.ko.md)

Each alert links to a section here. Every section answers the same three questions: what to check first, how to tell if it is a false positive, and what to do if it is real.

General rules for any real alert:
- **Preserve evidence before cleaning up.** Snapshot EBS volumes and copy logs before you delete anything.
- **Contain first, then investigate.** Revoking role sessions or attaching a deny policy is faster than understanding the whole attack.
- **Never paste personal data into chat or tickets** while you investigate. Use counts and formats.

## R1 role-denied

A monitored role got AccessDenied.

1. Check `From`. Is it one of your NAT IPs or a private IP?
   - **No**: the credentials are being used outside your network. Treat it as stolen.
   - **Yes**: it is most likely a missing permission after a deploy. Fix the permission.
2. If stolen:
   - Revoke active sessions: IAM → Roles → the role → *Revoke active sessions*. This also cuts healthy instances for a few minutes until they fetch new credentials.
   - Find how they got out: IMDSv1 enabled, SSRF, leaked keys. Look for `ec2RoleDelivery: "1.0"` in CloudTrail.
   - Require IMDSv2 on the instances.

## R2 role-offsite

A monitored role was used from a source IP outside `allowed_source_patterns`.

1. Look up the IP. Is it a new NAT gateway, a new VPC endpoint, or a CI runner you own? If so, add it to `allowed_source_patterns`.
2. Otherwise treat the credentials as stolen:
   - Attach a deny-outside-VPC policy (`examples/policies/deny-outside-vpc.json`). This stops the attacker immediately.
   - Revoke the role's active sessions.
   - Search CloudTrail for everything this role did from that IP: `userIdentity.arn` = the role and `sourceIPAddress` = the IP.

## R3 remote-exec

SSM Run Command, Session Manager, or ECS Exec was used by a principal outside `operator_principal_patterns`.

1. Check `Who`. Is it an instance or task role? Server roles should never run commands on other servers.
2. Open the command in Systems Manager → Run Command history, or the session log, and see what ran.
3. If unexpected:
   - Remove `ssm:SendCommand`, `ssm:StartSession` and `ecs:ExecuteCommand` from that principal.
   - Check every target instance for new users, SSH keys, cron jobs, systemd units, and files in `/tmp`.

## R4 iam-persistence

An IAM change that can create a backdoor: new users, access keys, login profiles, or policy changes.

1. Was this your CI/Terraform? If so, add its role to `deployer_principal_patterns`.
2. If not:
   - Deactivate any new access keys.
   - Delete new users and login profiles.
   - Revert policy and trust-policy changes.
   - Then look for what the same principal did before this change.

## R5 defense-evasion

CloudTrail, GuardDuty, Config, flow logs, or WAF logging was switched off or changed.

1. Turn the service back on first.
2. Then treat the principal in `Who` as compromised. Attackers do this right before the noisy part of an attack.

## R5b alarm-tamper

These alarms were changed: a rule was deleted or disabled, its targets were changed, or the SNS topic or subscription was changed.

1. Did you just deploy or update aws-breach-alarms? Then this is expected.
2. If not, redeploy the module to restore the rules, and confirm your email subscription still exists. Treat `Who` as compromised.

## R6 exfil-prep

A snapshot or AMI was shared, a bucket policy, ACL, or public access block changed, or a KMS key was disabled or scheduled for deletion.

1. For snapshot or AMI sharing, check `requestParameters` in CloudTrail for the account IDs that were added. Remove them if unknown.
2. For bucket changes, make sure Block Public Access is still on.
3. For KMS, cancel the key deletion (`CancelKeyDeletion`) within the waiting period.

## R7 console-signin

A root sign-in, a failed sign-in, or an IAM user sign-in without MFA.

1. **Root**: was it you? Root should almost never be used. If it wasn't you, reset the root password, check its MFA, and check its access keys.
2. **Failures**: a few typos are normal. Many failures from an unknown IP mean password guessing. Make sure MFA is on.
3. **No MFA**: enforce MFA for that user, or move them to IAM Identity Center.

## R8 waf-spike

A WAF rule you chose blocked more requests than the threshold.

1. Look at the blocked source IPs (WAF sampled requests, or ALB logs).
2. Repeated probing of vulnerable paths means someone is still trying. Make sure the underlying code is fixed; the WAF rule is only a stopgap.

## H1 delivery-failure

An alert could not be delivered and is waiting in the dead-letter queue.

1. Read the message in the DLQ (`<prefix>-dlq`). It is the undelivered alert. Handle it as that rule says.
2. Common causes:
   - The SNS topic policy or the KMS key policy no longer allows `events.amazonaws.com`.
   - The topic was deleted.
