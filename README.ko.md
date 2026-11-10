# aws-breach-alarms

[English](README.md)

비용이 거의 들지 않는 AWS 침해 탐지 알람입니다. CloudTrail → EventBridge → SNS 메일로 동작하며, Lambda와 서버 없이 월 1달러 미만입니다.

> 상태: 설계 단계 (v0.1). 아직 구현 전입니다.

공격자가 SSRF로 EC2 역할 자격증명(IMDSv1)을 탈취해 4일 동안 활동했지만, CloudTrail에 모든 기록이 있었는데도 알람이 하나도 울리지 않은 실제 사고에서 시작했습니다.

- 설계: [docs/design.ko.md](docs/design.ko.md)
- 침해사고 교훈 (식별정보 제거): [docs/lessons-learned.ko.md](docs/lessons-learned.ko.md)

## 규칙 (v0.1 예정)

| ID | 슬러그 | 탐지 |
|---|---|---|
| R1 | `role-denied` | 감시 역할의 권한 거부 (VPC 밖 사용 차단 정책에 걸린 탈취 자격증명) |
| R2 | `role-offsite` | 감시 역할을 허용되지 않은 출발지 IP에서 사용 |
| R3 | `remote-exec` | 허용되지 않은 주체의 SSM 명령·세션, ECS Exec |
| R4 | `iam-persistence` | IAM 사용자·액세스 키·로그인 프로필 생성, 정책 변경 |
| R5 | `defense-evasion` | CloudTrail·GuardDuty·Config·Flow Logs 무력화, 이 알람 자체의 변조 |
| R6 | `exfil-prep` | 스냅샷·AMI 공유, S3 정책·공개 설정 변경, KMS 키 삭제 |
| R7 | `console-signin` | 루트 로그인, 로그인 실패, MFA 없는 IAM 로그인 |
| R8 | `waf-spike` | 지정한 WAF 규칙의 차단 급증 (CloudWatch 알람) |
| H1 | `delivery-failure` | 알림 전달 실패 |

Terraform 모듈이나 CloudFormation 템플릿으로 배포합니다. 둘 다 하나의 규칙 정의에서 만들어집니다. 알림은 홈 리전 한 곳에서만 보내고, 다른 리전은 매칭된 이벤트를 홈 리전으로 전달합니다.

## 라이선스

MIT
