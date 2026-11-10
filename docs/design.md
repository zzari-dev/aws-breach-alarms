# aws-breach-alarms 설계 문서

- 상태: 초안 (v0.1)
- 라이선스: MIT
- 배경: [침해사고 교훈](lessons-learned.md)

## 1. 문제

탐지 서비스(GuardDuty, Security Hub, SIEM)는 비싸다. 작은 팀은 비용 때문에 이런 서비스를 끄고, 결국 **CloudTrail에 기록은 남는데 아무도 보지 않는** 상태가 된다. 실제 사고에서는 공격이 4일 동안 이어졌지만 알람이 하나도 울리지 않았고, 협박 메일을 받고서야 침해를 알았다.

## 2. 목표와 비목표

### 목표
- CloudTrail 관리 이벤트 중 **침해에 가까운 신호**만 골라 1~2분 안에 메일로 알린다.
- 비용은 **월 1달러 미만**으로 한다. Lambda, 서버, 별도 저장소를 쓰지 않는다.
- Terraform 모듈과 CloudFormation 템플릿 **두 가지로** 배포할 수 있게 한다. 규칙 정의는 한 곳에서만 관리한다.
- 설정값만 바꾸면 어느 계정에서든 쓸 수 있게 한다. 회사 고유 정보는 코드에 넣지 않는다.

### 비목표 (v0.1)
- GuardDuty를 대체하지 않는다. 머신러닝 기반 이상 탐지나 위협 인텔리전스는 하지 않는다.
- 웹 애플리케이션 로직 공격(IDOR 등)은 탐지하지 않는다. 이 공격은 CloudTrail에 남지 않는다.
- S3·Lambda 데이터 이벤트는 다루지 않는다. 추가 비용이 들기 때문이다.
- 자동 차단이나 격리 같은 대응 조치는 하지 않는다. 알림만 보낸다.

## 3. 구조

```
            ┌───────────────┐
CloudTrail ─▶  EventBridge   │  기본 이벤트 버스(default bus)
(관리 이벤트) │  규칙 R1~R5    │──▶ Input Transformer ──▶ SNS 토픽 ──▶ 메일
            └───────────────┘    (읽기 쉬운 문장으로 변환)     │
                                                              └──▶ (선택) AWS Chatbot → Slack
WAF 지표 ──▶ CloudWatch 알람 R6 ─────────────────────────────▶ SNS 토픽
```

- **EventBridge 기본 버스**: AWS 서비스 이벤트는 추가 요금 없이 들어온다. CloudTrail 트레일이 있어야 한다.
- **Input Transformer**: 이벤트 JSON에서 아래 필드를 뽑아 메일 본문을 만든다. 요금이 없다.
  - 누가: `userIdentity.arn`
  - 무엇을: `eventName`
  - 어디서: `sourceIPAddress`, `awsRegion`
  - 결과: `errorCode`
- **SNS**: 메일 구독은 월 1,000건까지 무료다. 토픽 정책은 `events.amazonaws.com`과 `cloudwatch.amazonaws.com`의 게시만 허용하고, `aws:SourceArn` 조건을 건다.

### 3.1 리전
- IAM, STS 전역 호출, 루트 콘솔 로그인 이벤트는 **us-east-1** 버스로만 들어온다.
- 그래서 모듈을 리전마다 배포하고, `enable_global_rules = true`인 리전(us-east-1)에서만 R3과 R5를 만든다.
- 서비스를 운영하는 리전에서는 R1, R2, R4, R6을 만든다.

## 4. 규칙 목록

모든 규칙은 `rules/<id>.json` 한 파일로 정의한다. 파일 안에는 메타데이터(ID, 제목, 심각도, 설명, 리전 범위)와 이벤트 패턴 템플릿이 들어간다. 패턴 안의 `${...}` 자리는 배포할 때 설정값으로 채운다.

### R1 — 서버 역할의 권한 거부 (심각도: 높음)
- **무엇을**: 지정한 역할(예: EC2 인스턴스 역할)의 세션에서 `errorCode`가 `AccessDenied`, `AccessDeniedException`, `Client.UnauthorizedOperation` 중 하나인 이벤트
- **왜**: 정상 서버 코드는 권한 오류를 거의 내지 않는다. 역할에 "VPC 밖에서는 거부" 정책을 걸어 두면, 탈취한 자격증명을 외부에서 쓸 때 **반드시 AccessDenied가 난다**. 이 규칙은 그 신호를 알림으로 바꾼다.
- **패턴 골자**:
  ```json
  {
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "userIdentity": { "arn": [{ "prefix": "arn:aws:sts::${account_id}:assumed-role/${role_name}/" }] },
      "errorCode": ["AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation"]
    }
  }
  ```
- **선행 조건(권장)**: 역할에 외부 사용 차단 deny 정책을 걸어 둔다. 예시 정책은 `examples/deny-outside-vpc.json`에 둔다.

### R2 — 원격 실행 (심각도: 높음)
- **무엇을**: `ssm:SendCommand`, `ssm:StartSession`, `ssm:ResumeSession`, `ecs:ExecuteCommand`를 **허용 주체가 아닌 주체**가 호출한 이벤트
- **허용 주체 기본값**:
  - SSO 관리자 역할 접두어 `AWSReservedSSO_`
  - SSM State Manager 서비스 역할
  - 사용자가 설정값으로 추가한 주체
- **왜**: 실제 사고에서 공격자는 탈취한 서버 역할로 SSM 명령을 약 190번, ECS Exec를 약 20번 실행했다.

### R3 — IAM 지속성 확보 (심각도: 높음, us-east-1 전용)
- **무엇을**: 아래 이벤트
  - `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`
  - `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`
  - `CreateRole`, `UpdateAssumeRolePolicy`
  - `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `AddUserToGroup`
  - `DeactivateMFADevice`, `DeleteVirtualMFADevice`
- **소음 제어**: 배포 파이프라인(Terraform 실행 역할 등)은 허용 주체로 빼는 옵션을 둔다.

### R4 — 흔적 삭제와 데이터 반출 준비 (심각도: 높음)
- **무엇을**: 아래 이벤트
  - CloudTrail: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`
  - GuardDuty: `DeleteDetector`, `UpdateDetector`
  - 스냅샷 공유: EC2 `ModifySnapshotAttribute`, RDS `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute`
  - S3: `PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`, `DeletePublicAccessBlock`
- **참고**: 스냅샷 속성 변경이 "외부 계정 추가"인지 정밀하게 거르는 건 v0.2에서 한다. v0.1은 이벤트 이름만으로 알린다. 이 이벤트들은 원래 드물다.

### R5 — 계정 로그인 (심각도: 높음/중간, us-east-1 전용)
- **무엇을**:
  - 루트 계정 콘솔 로그인 (높음)
  - 콘솔 로그인 실패 (중간)
- `detail-type`은 `AWS Console Sign In via CloudTrail`이다.

### R6 — WAF 차단 급증 (심각도: 중간, 선택 사항)
- **무엇을**: 지정한 WebACL과 규칙의 `AWS/WAFV2 BlockedRequests` 합계가 5분간 N건 이상
- **왜**: 취약 경로 차단 규칙에 걸리는 요청은 공격자가 다시 시도한다는 직접적인 신호다.
- **비용**: CloudWatch 알람 1개, 월 0.10달러

## 5. 설정값

| 이름 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `name_prefix` | string | `breach-alarms` | 리소스 이름 접두어 |
| `alert_emails` | list(string) | — | SNS 메일 구독 주소. 처음 한 번 구독 확인이 필요하다 |
| `enable_global_rules` | bool | `false` | R3과 R5 생성 여부. us-east-1에서만 `true` |
| `monitored_role_names` | list(string) | `[]` | R1이 감시할 역할 이름. 비어 있으면 R1을 만들지 않는다 |
| `trusted_principal_arn_prefixes` | list(string) | SSO 역할 접두어 | R2와 R3에서 제외할 주체 |
| `waf_alarms` | list(object) | `[]` | R6용 `{ web_acl, rule, threshold }` |
| `disabled_rules` | list(string) | `[]` | 끌 규칙 ID |
| `kms_key_arn` | string | `null` | SNS 토픽 암호화용 키 (선택) |

## 6. 저장소 구조

```
aws-breach-alarms/
├─ rules/                  # 원본(single source of truth): 규칙 메타데이터 + 패턴 템플릿
├─ terraform/              # Terraform 모듈 (rules/*.json을 file()+jsondecode로 읽음)
│  └─ examples/{single-region,multi-region}/
├─ cloudformation/
│  └─ template.yaml        # scripts/build_cfn.py가 생성 (직접 수정 금지)
├─ scripts/build_cfn.py
├─ examples/deny-outside-vpc.json   # R1 선행 조건 정책 예시
├─ tests/
│  ├─ events/<rule>/{match,nomatch}/*.json   # 가명 처리한 CloudTrail 이벤트
│  └─ test_*.py
├─ docs/{design.md, lessons-learned.md}
├─ README.md, README.ko.md, LICENSE, SECURITY.md
└─ .github/workflows/ci.yml
```

## 7. 테스트 전략 (TDD)

1. **패턴 테스트(핵심)**: 규칙마다 탐지돼야 할 이벤트(match)와 걸리면 안 되는 이벤트(nomatch)를 둔다. 패턴을 고치기 전에 실패하는 테스트부터 추가한다.
   - 테스트 데이터는 실제 사고의 이벤트 형태를 쓰고, 계정 ID와 IP는 가명으로 바꾼다.
   - 판정 엔진은 실제 AWS 동작과 같아야 한다. 그래서 `aws events test-event-pattern` API를 쓴다(자격증명은 필요하지만 리소스를 만들지 않고 무료).
   - 오프라인 대안으로 moto의 패턴 매처를 검토했다. `anything-but`과 `prefix` 조합 지원이 확인되지 않아 보조로만 쓴다.
2. **생성물 일치 테스트**: `build_cfn.py`의 결과가 커밋된 `template.yaml`과 같은지 확인한다. CI에서 생성기를 다시 돌려 차이가 있으면 실패시킨다.
3. **정적 검사**: `terraform fmt -check`, `terraform validate`, `terraform test`(mock provider), `cfn-lint`
4. **배포 후 수동 검증**: 테스트 계정에서 R3을 트리거해 메일이 오는지 확인한다(예: 임시 IAM 사용자 생성 후 삭제). 절차는 README에 적는다.

## 8. 비용 (월, 서울 리전 기준)

| 항목 | 비용 |
|---|---|
| EventBridge 규칙, AWS 서비스 이벤트 수신 | 0 |
| Input Transformer | 0 |
| SNS 메일 (1,000건까지) | 0 |
| CloudWatch 알람 (R6, 1개당) | 약 0.10달러 |
| **합계** | **1달러 미만** |

참고로 CloudTrail 트레일이 없으면 하나 만들어야 한다. 관리 이벤트 첫 사본은 무료이고 S3 저장 비용만 든다.

## 9. 확인이 필요한 사항 (구현 전에 검증)

1. **읽기 전용 관리 이벤트(Get, List, Describe)가 EventBridge로 전달되는지**
   - 기본 상태(`ENABLED`)에서는 전달되지 않고, 규칙 상태를 `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`로 해야 받는 것으로 알고 있다.
   - 이 값과 과금 여부를 공식 문서로 확인한다.
   - R1은 읽기 전용 API의 AccessDenied도 잡아야 하므로 이 설정이 필요할 가능성이 높다.
2. **`anything-but` 안에 `prefix` 여러 개를 넣을 수 있는지**: R2와 R3의 허용 주체 목록에 필요하다. 안 되면 규칙을 나누거나 `wildcard`를 쓴다.
3. **콘솔 로그인 이벤트의 리전**: 루트가 아닌 IAM 사용자는 로그인한 엔드포인트 리전으로 들어올 수 있다. 문서로 확인한다.
4. **CloudFormation에서 설정값 목록 다루기**: 템플릿 파라미터는 리스트 처리가 제한적이다. 규칙별 조건(Conditions)과 `Fn::Split`으로 처리할 수 있는지 확인한다.

## 10. 보안과 공개 원칙

- 저장소에 계정 ID, IP, 도메인, 회사·서비스명, 실제 역할 이름을 넣지 않는다.
- 테스트 이벤트는 AWS 문서의 예시 계정 ID(`123456789012`)와 문서용 IP 대역(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)만 쓴다.
- 공개 전에 `gitleaks`로 시크릿을 검사하고, 사람이 직접 한 번 더 검토한다.
- `SECURITY.md`에 취약점 제보 경로를 적는다.

## 11. 로드맵

- **v0.1**: R1~R6, Terraform과 CloudFormation, 메일 알림
- **v0.2**:
  - AWS Chatbot으로 Slack 알림 (무료)
  - 스냅샷의 외부 계정 공유 정밀 필터
  - 보안 그룹을 `0.0.0.0/0`으로 여는 변경 탐지
- **v0.3 (선택, 소액 비용)**:
  - ALB 접근 로그를 검사하는 Lambda (경로 조작, SSRF 패턴, 대량 열거)
  - 알림 내용을 보강하는 Lambda (IP 국가, 허용 IP 목록 판정)
