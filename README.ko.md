# aws-breach-alarms

[English](README.md)

비용이 거의 들지 않는 AWS 침해 탐지 알람입니다. CloudTrail → EventBridge → SNS 메일로 동작하며, Lambda와 서버 없이 월 1달러 미만입니다.

> 상태: v0.1, 정식 릴리스 전. 패턴은 실제 EventBridge API로 검증했습니다. 실제 계정 배포 테스트는 아직 남아 있습니다.

공격자가 SSRF로 EC2 역할 자격증명(IMDSv1)을 탈취해 4일 동안 활동했지만, CloudTrail에 모든 기록이 있었는데도 알람이 하나도 울리지 않은 실제 사고에서 시작했습니다.

- 설계: [docs/design.ko.md](docs/design.ko.md)
- 침해사고 교훈 (식별정보 제거): [docs/lessons-learned.ko.md](docs/lessons-learned.ko.md)

## 규칙 (v0.1)

| ID | 슬러그 | 탐지 |
|---|---|---|
| R1 | `role-denied` | 감시 역할의 권한 거부 (VPC 밖 사용 차단 정책에 걸린 탈취 자격증명) |
| R2 | `role-offsite` | 감시 역할을 허용되지 않은 출발지 IP에서 사용 |
| R3 | `remote-exec` | 허용되지 않은 주체의 SSM 명령·세션, ECS Exec |
| R4 | `iam-persistence` | IAM 사용자·액세스 키·로그인 프로필 생성, 정책 변경 |
| R5 | `defense-evasion` | CloudTrail·GuardDuty·Config·Flow Logs·WAF 로그 무력화 |
| R5b | `alarm-tamper` | 이 알람의 변조 (규칙, 대상, SNS 토픽·구독) |
| R6 | `exfil-prep` | 스냅샷·AMI 공유, S3 정책·공개 설정 변경, KMS 키 삭제 |
| R7 | `console-signin` | 루트 로그인, 로그인 실패, MFA 없는 IAM 로그인 |
| R8 | `waf-spike` | 지정한 WAF 규칙의 차단 급증 (CloudWatch 알람) |
| H1 | `delivery-failure` | 알림 전달 실패 |

Terraform 모듈이나 CloudFormation 템플릿으로 배포합니다. 둘 다 하나의 규칙 정의에서 만들어집니다. 알림은 홈 리전 한 곳에서만 보내고, 다른 리전은 매칭된 이벤트를 홈 리전으로 전달합니다.

## 빠른 시작 (Terraform)

```hcl
module "breach_alarms" {
  source = "github.com/zzari-dev/aws-breach-alarms?ref=v0.1.0"

  alert_emails            = ["security@example.com"]
  monitored_role_names    = ["app-server-role"]                       # R1/R2
  allowed_source_patterns = ["203.0.113.10", "10.*", "*.amazonaws.com", "AWS Internal"]  # NAT IP 등
}
```

- 구독 확인 메일을 한 번 클릭해야 합니다.
- IAM 이벤트와 루트 로그인은 us-east-1(과 몇몇 리전)에 기록됩니다. 그 리전에는 `mode = "forwarder"` 모듈을 추가하세요. [examples/terraform/multi-region](examples/terraform/multi-region/main.tf)을 참고하세요.
- R1과 함께 쓰기를 권장합니다: [examples/policies/deny-outside-vpc.json](examples/policies/)

## 빠른 시작 (CloudFormation)

[cloudformation/template.json](cloudformation/template.json)을 배포합니다.
- 메인 리전에는 `Mode=home`과 `AlertEmail`로 한 번 배포합니다.
- 나머지 리전에는 `Mode=forwarder`와 `HomeRegion`으로 배포합니다. StackSets로 배포해도 됩니다.

## 비용

월 약 0.2~0.5달러입니다.
- EventBridge 규칙과 AWS 서비스 이벤트 수신은 무료입니다.
- SNS 메일은 월 1,000건까지 무료입니다.
- CloudWatch 알람은 개당 0.10달러입니다.
- CloudTrail 트레일이 있어야 합니다.

## 테스트 방식

- 규칙마다 탐지돼야 할 이벤트와 걸리면 안 되는 이벤트가 있습니다(`tests/events/`).
- 이 이벤트들은 EventBridge가 실제로 쓰는 엔진 [aws/event-ruler](https://github.com/aws/event-ruler)로 오프라인에서 판정합니다. `make verify-aws`를 실행하면 실제 `TestEventPattern` API로 교차 검증합니다.
- Terraform 모듈(오프라인 plan)과 CloudFormation 템플릿은 똑같은 패턴과 메시지를 만들어야 테스트를 통과합니다.

기여 방법은 [CONTRIBUTING.md](CONTRIBUTING.md), 알림 대응은 [docs/runbook.ko.md](docs/runbook.ko.md)를 보세요.

## 라이선스

MIT
