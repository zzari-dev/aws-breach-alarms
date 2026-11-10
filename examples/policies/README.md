# deny-outside-vpc.json

Attach as an inline policy to an instance or task role. It makes stolen role credentials useless outside your network. Each denied call then triggers **R1 role-denied**.

A request is denied only when **all three** hold:

| Condition | Passes (not denied) when |
|---|---|
| `aws:SourceVpc` is not your VPC | The call came through a VPC endpoint in your VPC |
| `aws:SourceIp` is not your NAT IP | The call went out through your NAT gateway |
| `aws:ViaAWSService` is false | An AWS service called on your behalf (e.g. KMS via Secrets Manager) |

Replace `vpc-0123456789abcdef0` and `203.0.113.10/32` with your VPC IDs and NAT gateway public IPs. List every VPC and NAT the role is used from.

Roll it out carefully:

1. Deploy aws-breach-alarms with the role in `monitored_role_names` and `allowed_source_patterns` set. **R2 role-offsite** shows any legitimate source you forgot, before anything is blocked.
2. After a quiet week, attach this policy.
