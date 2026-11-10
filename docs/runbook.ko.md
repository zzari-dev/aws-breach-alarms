# 대응 런북

[English](runbook.md)

알림 메일마다 이 문서의 해당 항목 링크가 붙는다. 각 항목은 세 가지에 답한다.
- 먼저 무엇을 확인하는가
- 오탐인지 어떻게 가리는가
- 실제 공격이면 무엇을 하는가

실제 공격일 때 공통 원칙:
- **정리하기 전에 증거부터 보존한다.** 무언가를 지우기 전에 EBS 스냅샷과 로그 사본을 만든다.
- **먼저 막고, 그다음에 조사한다.** 역할 세션 무효화나 deny 정책 적용이 전체 공격을 파악하는 것보다 빠르다.
- **조사 중에 개인정보를 채팅이나 티켓에 붙이지 않는다.** 건수와 형식만 본다.

## R1 role-denied

감시 역할에서 AccessDenied가 났다.

1. `From`이 회사 NAT IP나 사설 IP인지 확인한다.
   - **아니면**: 자격증명을 회사 밖에서 쓰고 있다. 탈취로 본다.
   - **맞으면**: 대부분 배포 후 권한 누락이다. 권한을 고친다.
2. 탈취라면:
   - 활성 세션을 무효화한다(IAM → 역할 → *Revoke active sessions*). 정상 인스턴스도 새 자격증명을 받을 때까지 몇 분간 끊긴다.
   - 유출 경로를 찾는다: IMDSv1, SSRF, 키 유출. CloudTrail에서 `ec2RoleDelivery: "1.0"`을 찾아본다.
   - 인스턴스에 IMDSv2를 필수로 설정한다.

## R2 role-offsite

감시 역할이 `allowed_source_patterns` 밖의 IP에서 쓰였다.

1. IP를 확인한다. 새 NAT 게이트웨이, 새 VPC 엔드포인트, 회사 CI 러너라면 `allowed_source_patterns`에 추가한다.
2. 아니면 탈취로 보고:
   - VPC 밖 사용 차단 정책(`examples/policies/deny-outside-vpc.json`)을 붙인다. 공격자가 바로 막힌다.
   - 역할의 활성 세션을 무효화한다.
   - CloudTrail에서 이 역할이 그 IP로 한 일을 모두 찾는다(`userIdentity.arn`과 `sourceIPAddress`로 검색).

## R3 remote-exec

`operator_principal_patterns` 밖의 주체가 SSM 명령, 세션, ECS Exec를 실행했다.

1. `Who`를 확인한다. 인스턴스 역할이나 태스크 역할이면 이상 징후다. 서버 역할이 다른 서버에 명령을 내릴 일은 없다.
2. Systems Manager → Run Command 기록이나 세션 로그에서 무엇을 실행했는지 본다.
3. 예상하지 못한 실행이면:
   - 그 주체에서 `ssm:SendCommand`, `ssm:StartSession`, `ecs:ExecuteCommand`를 뺀다.
   - 대상 인스턴스마다 새 사용자, SSH 키, cron, systemd 서비스, `/tmp` 파일을 점검한다.

## R4 iam-persistence

백도어가 될 수 있는 IAM 변경이 있었다: 사용자, 액세스 키, 로그인 프로필 생성, 정책 변경 등.

1. CI나 Terraform 배포였나? 그렇다면 그 역할을 `deployer_principal_patterns`에 추가한다.
2. 아니라면:
   - 새 액세스 키를 비활성화한다.
   - 새 사용자와 로그인 프로필을 지운다.
   - 정책과 신뢰 정책 변경을 되돌린다.
   - 같은 주체가 그 전에 한 일을 추적한다.

## R5 defense-evasion

CloudTrail, GuardDuty, Config, Flow Logs, WAF 로깅이 꺼지거나 바뀌었다.

1. 먼저 서비스를 다시 켠다.
2. 그다음 `Who`의 주체를 탈취된 것으로 본다. 공격자는 본격적으로 움직이기 직전에 이 작업을 한다.

## R5b alarm-tamper

이 알람이 변경됐다: 규칙 삭제·비활성화, 대상 변경, SNS 토픽·구독 변경.

1. 방금 aws-breach-alarms를 배포하거나 업데이트했나? 그렇다면 정상이다.
2. 아니라면 모듈을 다시 배포해 규칙을 복구하고, 메일 구독이 남아 있는지 확인한다. `Who`는 탈취된 것으로 본다.

## R6 exfil-prep

스냅샷·AMI 공유, 버킷 정책·ACL·퍼블릭 액세스 차단 변경, KMS 키 비활성화·삭제 예약이 있었다.

1. 스냅샷·AMI 공유는 CloudTrail의 `requestParameters`에서 추가된 계정 ID를 확인한다. 모르는 계정이면 제거한다.
2. 버킷 변경이면 Block Public Access가 켜져 있는지 확인한다.
3. KMS 키 삭제 예약은 대기 기간 안에 `CancelKeyDeletion`으로 취소한다.

## R7 console-signin

루트 로그인, 로그인 실패, MFA 없는 IAM 사용자 로그인이 있었다.

1. **루트**: 본인이었나? 루트는 거의 쓰지 않아야 한다. 아니라면 루트 비밀번호를 바꾸고 MFA와 액세스 키를 점검한다.
2. **실패**: 오타 몇 번은 정상이다. 모르는 IP에서 반복된 실패는 비밀번호 대입 공격이다. MFA가 켜져 있는지 확인한다.
3. **MFA 없음**: 그 사용자에게 MFA를 강제하거나 IAM Identity Center로 옮긴다.

## R8 waf-spike

지정한 WAF 규칙의 차단 수가 기준치를 넘었다.

1. WAF 샘플 요청이나 ALB 로그에서 차단된 출발지 IP를 확인한다.
2. 취약 경로를 반복해서 찌른다면 누군가 계속 시도하고 있다는 뜻이다. 원인 코드가 수정됐는지 확인한다. WAF 규칙은 임시방편일 뿐이다.

## H1 delivery-failure

알림을 전달하지 못해 DLQ에 쌓였다.

1. DLQ(`<prefix>-dlq`)의 메시지를 확인한다. 전달되지 못한 알림이므로 해당 규칙 항목대로 처리한다.
2. 흔한 원인:
   - SNS 토픽 정책이나 KMS 키 정책이 `events.amazonaws.com`을 허용하지 않는다.
   - 토픽이 삭제됐다.
