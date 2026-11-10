# aws-breach-alarms 설계 문서

- 상태: 검토 중 (v0.1)
- 라이선스: MIT
- 영문: [design.md](design.md)
- 배경: [침해사고 교훈](lessons-learned.ko.md)

## 1. 문제

탐지 서비스(GuardDuty, Security Hub, SIEM)는 비싸다. 작은 팀은 비용 때문에 이런 서비스를 끄고, 결국 **CloudTrail에 기록은 남는데 아무도 보지 않는** 상태가 된다. 실제 사고에서는 공격이 4일 동안 이어졌지만 알람이 하나도 울리지 않았고, 협박 메일을 받고서야 침해를 알았다.

## 2. 목표와 비목표

### 목표
- CloudTrail 관리 이벤트 중 **침해에 가까운 신호**만 골라 1~2분 안에 메일로 알린다.
- 비용은 **월 1달러 미만**으로 한다. Lambda와 서버를 쓰지 않는다.
- Terraform 모듈과 CloudFormation 템플릿 두 가지로 배포할 수 있게 한다. 규칙 정의는 한 곳에서만 관리한다.
- 설정값만 바꾸면 어느 계정에서든 쓸 수 있게 한다.
- 알람 체계 자체가 꺼지거나 고장 나도 그 사실을 알 수 있게 한다.

### 비목표 (v0.1)
- GuardDuty를 대체하지 않는다. 머신러닝 기반 이상 탐지나 위협 인텔리전스는 하지 않는다.
- 웹 애플리케이션 로직 공격(IDOR, SQL 인젝션 등)은 탐지하지 않는다. 이런 공격은 CloudTrail에 남지 않는다.
- S3·Lambda **데이터 이벤트**는 다루지 않는다. CloudTrail 추가 요금이 붙는다.
- 자동 차단·격리 같은 대응 조치는 하지 않는다. 알림만 보낸다.
- 여러 계정(AWS Organizations)을 한 곳에서 모아 보는 기능은 다루지 않는다. 로드맵에 넣었다.

## 3. 대안 검토

| 대안 | 월 비용 | 채택하지 않은 이유 |
|---|---|---|
| GuardDuty | CloudTrail 이벤트 양에 비례 (대량 호출 계정은 수십~수백 달러) | 비싸서 꺼 두는 팀이 많다. 함께 쓰는 것은 권장한다 |
| CloudTrail → CloudWatch Logs + 지표 필터 | 로그 수집 GB당 약 0.76달러 | 이벤트가 많은 계정은 수집 비용이 커진다 |
| Lambda가 CloudTrail을 주기적으로 조회 | 수 센트 | 조회 API가 초당 2회로 제한돼 대량 이벤트를 다 볼 수 없고, 탐지가 늦다 |
| AWS User Notifications | 무료 | 콘솔 중심이라 규칙을 코드로 관리하기 어렵고, 규칙 묶음을 배포하기 불편하다 |
| **EventBridge 규칙 → SNS (채택)** | **약 0** | 패턴 표현력에 한계가 있다(9장) |

## 4. 구조

```
             [홈 리전]
CloudTrail ─▶ EventBridge 기본 버스 ─▶ 규칙 R1~R7 ─▶ Input Transformer ─▶ SNS ─▶ 메일
                    ▲                                                     ▲     └▶ (선택) Slack
                    │ 이벤트 전달(PutEvents)                               │
             [전달 리전들]                                                  │
CloudTrail ─▶ 기본 버스 ─▶ 전달 규칙(R4·R7 등) ─┘          WAF 지표 ─▶ CloudWatch 알람 R8
                                                     EventBridge 실패 지표 ─▶ 알람 H1
```

### 4.1 구성 요소
- **EventBridge 기본 버스**: CloudTrail 이벤트는 기본 버스로만 들어온다. 활성화된 CloudTrail 트레일이 있어야 한다.
- **규칙 상태**:
  - 쓰기 이벤트만 보는 규칙은 기본값 `ENABLED`로 둔다.
  - 읽기 전용 API(Get·List·Describe)까지 봐야 하는 규칙(R1, R2)은 **`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`** 로 둔다. 이 상태는 CloudFormation과 Terraform(`state` 인자)에서 지원된다.
- **Input Transformer**: 이벤트 JSON에서 필드를 뽑아 읽기 쉬운 메일 본문을 만든다(6장).
- **SNS 토픽**: 메일 구독자를 둔다. 토픽 정책은 `events.amazonaws.com`과 `cloudwatch.amazonaws.com`만 게시할 수 있게 하고, `aws:SourceAccount` 조건을 건다.
- **DLQ(SQS)**: EventBridge가 SNS로 전달하지 못한 이벤트를 보관한다.

### 4.2 리전 전략 — 홈 리전과 전달 리전
CloudTrail 이벤트는 **그 이벤트가 기록된 리전의 버스로만** 들어온다. 리전마다 특성이 다르다.

| 이벤트 | 기록되는 리전 |
|---|---|
| IAM, STS 전역 엔드포인트 | us-east-1 |
| 루트 콘솔 로그인 | us-east-1, us-east-2, us-west-2 중 하나 |
| IAM 사용자 콘솔 로그인 (전역 엔드포인트) | us-east-1, 또는 us-east-2, eu-north-1, ap-southeast-2 중 하나 |
| IAM 사용자 콘솔 로그인 (리전 엔드포인트) | 그 엔드포인트의 리전 |
| 워크로드 API 호출 | 워크로드가 있는 리전 |

- 리전마다 SNS 토픽을 만들면 리전 수만큼 구독 확인 메일이 오고 관리도 번거롭다.
- 그래서 **알림은 홈 리전 하나에서만** 보낸다. 다른 리전에는 전달 규칙만 두고, 매칭된 이벤트를 홈 리전 기본 버스로 보낸다(EventBridge 리전 간 버스 대상).
- 모듈은 `mode = "home" | "forwarder"`로 동작을 나눈다.
- 읽기 전용 이벤트를 전달할 때는 **전달 규칙과 홈 리전 규칙 모두** `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`여야 한다(AWS 문서 기준).
- **권장 배포 리전**: 홈 리전, us-east-1, us-east-2, us-west-2, eu-north-1, ap-southeast-2, 그리고 워크로드가 있는 모든 리전

## 5. 규칙 목록

모든 규칙은 `rules/<id>.json` 하나로 정의한다. 파일에는 아래가 들어간다.
- ID와 슬러그
- 제목과 심각도
- 설명과 대응 가이드
- 규칙 상태(`ENABLED` 또는 `ALL`)
- 적용 리전(`home`, `global`, `signin`, `any`)
- 이벤트 패턴 템플릿 (`${...}` 자리는 배포할 때 설정값으로 채운다)

| ID | 슬러그 | 심각도 | 상태 | 탐지 |
|---|---|---|---|---|
| R1 | `role-denied` | 높음 | ALL | 감시 역할에서 권한 거부 |
| R2 | `role-offsite` | 높음 | ALL | 감시 역할을 허용되지 않은 출발지에서 사용 |
| R3 | `remote-exec` | 높음 | ENABLED | 허용 주체가 아닌 원격 명령 실행 |
| R4 | `iam-persistence` | 높음 | ENABLED | IAM 백도어 생성 |
| R5 | `defense-evasion` | 높음 | ENABLED | 로깅·탐지·알람 무력화 |
| R6 | `exfil-prep` | 높음 | ENABLED | 데이터 외부 공유 준비 |
| R7 | `console-signin` | 높음/중간 | ENABLED | 루트 로그인, 로그인 실패, MFA 없는 로그인 |
| R8 | `waf-spike` | 중간 | (지표 알람) | WAF 특정 규칙 차단 급증 |
| H1 | `delivery-failure` | 높음 | (지표 알람) | 알림 전달 실패 |

### R1 `role-denied` — 감시 역할의 권한 거부
- **조건**: 감시 역할의 세션에서 `errorCode`가 `AccessDenied`, `AccessDeniedException`, `Client.UnauthorizedOperation`, `UnauthorizedOperation` 중 하나
- **왜**: 정상 서버 코드는 권한 오류를 거의 내지 않는다. 역할에 "VPC 밖 사용 거부" 정책을 걸어 두면 탈취한 자격증명을 외부에서 쓸 때 반드시 거부가 나고, 이 규칙이 그 거부를 알림으로 바꾼다.
- **선행 조건(권장)**: `examples/policies/deny-outside-vpc.json`
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
- 감시 역할마다 `arn` 값을 하나씩 추가한다(OR 조건).

### R2 `role-offsite` — 감시 역할을 허용되지 않은 출발지에서 사용
- **조건**: 감시 역할 세션의 `sourceIPAddress`가 허용 패턴에 없음
- **허용 패턴 예**: NAT 공인 IP, VPC 엔드포인트를 거친 사설 IP(`10.*`), AWS 서비스 대리 호출(`*.amazonaws.com`), `AWS Internal`
  ```json
  "sourceIPAddress": [{ "anything-but": { "wildcard": ${allowed_source_patterns} } }]
  ```
- **왜**: 실제 사고에서 공격자가 처음 한 일은 외부 IP에서 탈취한 자격증명으로 `GetCallerIdentity`를 호출하는 것이었다. R1과 달리 **deny 정책이 없어도** 잡는다.
- **주의**:
  - 와일드카드는 옥텟 단위(`10.*`)로만 넓힐 수 있다. CIDR 부정 연산자(`anything-but` + `cidr`)는 지원되지 않는다.
  - 읽기 전용 이벤트를 모두 패턴에 대 보게 되지만, 패턴에 맞는 것만 SNS로 간다.
- `allowed_source_patterns`가 비어 있으면 R2를 만들지 않는다.

### R3 `remote-exec` — 원격 명령 실행
- **조건**: `ssm:SendCommand`, `ssm:StartSession`, `ssm:ResumeSession`, `ecs:ExecuteCommand`를 허용 주체가 아닌 주체가 호출
  ```json
  "userIdentity": { "arn": [{ "anything-but": { "wildcard": ${trusted_principal_patterns} } }] }
  ```
- **허용 주체 기본값**: `arn:aws:sts::${account_id}:assumed-role/AWSReservedSSO_*`, `arn:aws:sts::${account_id}:assumed-role/AWSServiceRoleForAmazonSSM/*`
- **왜**: 실제 사고에서 공격자는 탈취한 서버 역할로 SSM 명령을 약 190번, ECS Exec를 약 20번 실행했다.
- **확인 필요**: `userIdentity.arn`이 없는 이벤트(`type: AWSService`)를 `anything-but`이 어떻게 판정하는지. 테스트로 확정한다.

### R4 `iam-persistence` — IAM 백도어 생성 (us-east-1)
- **조건**: 아래 이벤트(`eventSource: iam.amazonaws.com`)를 허용 주체가 아닌 주체가 호출
  - `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`
  - `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, `AttachGroupPolicy`, `PutGroupPolicy`
  - `CreateRole`, `UpdateAssumeRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `AddUserToGroup`
  - `DeactivateMFADevice`, `DeleteVirtualMFADevice`
  - `CreateOpenIDConnectProvider`, `CreateSAMLProvider`
- **허용 주체**: 배포 파이프라인(Terraform 실행 역할 등)을 넣어 소음을 줄인다. 기본값은 비어 있어서 모든 변경을 알린다.

### R5 `defense-evasion` — 로깅·탐지·알람 무력화
- **조건**: 아래 이벤트
  - CloudTrail: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`
  - GuardDuty: `DeleteDetector`, `UpdateDetector`, `DisassociateFromMasterAccount`
  - Config: `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`
  - VPC·WAF 로그: `DeleteFlowLogs`, `DeleteLoggingConfiguration`
  - Security Hub: `DisableSecurityHub`
  - **이 프로젝트 자체 보호**:
    - `events:DeleteRule`, `DisableRule`, `RemoveTargets`, `PutRule`, `PutTargets` 중 이름이 `${name_prefix}`로 시작하는 규칙
    - `sns:DeleteTopic`, `Unsubscribe`, `SetTopicAttributes`, `RemovePermission` 중 우리 토픽 대상
- **한계**: 규칙을 지우는 바로 그 이벤트는 지워지는 규칙이 처리하지 못할 수 있다. 그래서 자체 보호 패턴은 별도 규칙(`R5b`)으로 나눠, 공격자가 한 번에 모든 규칙을 지우기 어렵게 한다.

### R6 `exfil-prep` — 데이터 외부 공유 준비
- **조건**: 아래 이벤트
  - 스냅샷·이미지 공유: EC2 `ModifySnapshotAttribute`, `ModifyImageAttribute`, RDS `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute`
  - S3 공개: `PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`, `DeletePublicAccessBlock`, `PutAccountPublicAccessBlock`(s3control)
  - KMS: `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy`
- **v0.2**: 스냅샷 공유 중 "외부 계정 추가"만 골라내는 정밀 필터

### R7 `console-signin` — 콘솔 로그인 (로그인 리전)
- `detail-type: "AWS Console Sign In via CloudTrail"`, `eventName: ConsoleLogin`
  - **R7a 루트 로그인** (높음): `userIdentity.type = Root`. 성공과 실패 모두 알린다.
  - **R7b 로그인 실패** (중간): `responseElements.ConsoleLogin = Failure`
  - **R7c MFA 없는 로그인** (중간): `additionalEventData.MFAUsed = No`, `userIdentity.type = IAMUser`
    - SSO(페더레이션) 로그인은 MFA가 IdP 쪽에서 처리돼 `No`로 찍히므로 이 규칙에서 뺀다.

### R8 `waf-spike` — WAF 차단 급증 (선택)
- **조건**: `AWS/WAFV2 BlockedRequests`(WebACL, Rule, Region 차원) 합계가 5분간 `threshold` 이상
- **왜**: 취약 경로 차단 규칙에 걸리는 요청은 공격자가 다시 시도한다는 신호다.
- `waf_alarms` 항목 하나당 CloudWatch 알람 1개(월 0.10달러)

### H1 `delivery-failure` — 알림 체계 자체 감시
- **조건**: `AWS/Events FailedInvocations`(우리 규칙들) 합계 > 0, 또는 DLQ의 `ApproximateNumberOfMessagesVisible` > 0
- **왜**: 탐지는 됐는데 알림이 안 가는 상황을 알아차리게 한다.

## 6. 알림 메시지

EventBridge 대상에는 SNS 메일 제목을 정할 수 없다(기본값 "AWS Notification Message"). 그래서 **본문 첫 줄을 사실상의 제목**으로 쓴다.

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

- 제목, 심각도, "Why it matters", 런북 링크는 규칙 메타데이터에서 고정 문자열로 넣는다.
- 나머지는 `InputPathsMap`으로 뽑는다(`$.detail.eventName` 등).
- 경로가 없는 필드는 빈 값으로 나온다.

## 7. 설정값

| 이름 | 타입 | 기본값 | 설명 |
|---|---|---|---|
| `mode` | string | `"home"` | `home`이면 SNS와 알람을 만들고, `forwarder`면 홈 리전으로 전달만 한다 |
| `home_region` | string | — | forwarder가 이벤트를 보낼 리전 |
| `name_prefix` | string | `"breach-alarms"` | 리소스 이름 접두어. R5 자체 보호에도 쓴다 |
| `alert_emails` | list(string) | `[]` | home 전용. 처음 한 번 구독 확인이 필요하다 |
| `enabled_rules` | list(string) | 리전 역할에 맞는 기본 목록 | 만들 규칙 ID |
| `monitored_role_names` | list(string) | `[]` | R1·R2 대상 역할. 비어 있으면 R1·R2를 만들지 않는다 |
| `allowed_source_patterns` | list(string) | `[]` | R2 허용 출발지 와일드카드 |
| `trusted_principal_patterns` | list(string) | SSO·SSM 서비스 역할 | R3·R4 제외 주체 와일드카드 |
| `waf_alarms` | list(object) | `[]` | R8: `{ web_acl, rule, region, threshold }` |
| `kms_key_arn` | string | `null` | SNS와 SQS 암호화용 키 (선택) |
| `tags` | map(string) | `{}` | 공통 태그 |

**출력값**: `sns_topic_arn`, `rule_arns`, `dlq_arn`, `forwarder_role_arn`

**CloudFormation**:
- 같은 파라미터를 쓴다. 목록 값은 `CommaDelimitedList`로 받는다.
- `Mode`, `EnableR1` 같은 조건(Conditions)으로 리소스 생성을 켜고 끈다.
- 여러 리전 배포는 StackSets 또는 리전마다 스택 생성으로 한다.

## 8. 오탐과 소음 관리

| 규칙 | 예상 빈도 (작은 계정) | 오탐 원인 | 조정 방법 |
|---|---|---|---|
| R1 | 거의 없음 | 앱 배포 직후 권한 누락 | 권한을 고친다 (오탐이 아니라 수정할 신호) |
| R2 | 거의 없음 | NAT IP 변경, 새 VPC 엔드포인트 | `allowed_source_patterns` 갱신 |
| R3 | 운영자 작업 시 | 운영자가 SSO가 아닌 경로로 접속 | 운영 주체를 허용 목록에 추가 |
| R4 | 인프라 배포 시 | Terraform·CI 역할 | 배포 역할을 허용 목록에 추가 |
| R5 | 매우 드묾 | 이 모듈을 업데이트할 때 | 배포 중 알림은 정상으로 본다 |
| R6 | 드묾 | 정상적인 버킷 정책 변경 | v0.2 정밀 필터 |
| R7 | 비밀번호 오타 | 로그인 실패 | R7b를 끈다 |

## 9. 알려진 한계

- **패턴만으로 판정한다**: 횟수 기준(예: 5분 동안 10회 이상)이나 상관관계 분석은 할 수 없다.
- **CIDR 부정 연산자가 없다**: R2의 허용 출발지는 옥텟 단위 와일드카드로만 표현한다.
- **CloudTrail 지연**: 이벤트가 버스에 들어오기까지 보통 수 분 걸린다.
- **데이터 이벤트 미포함**: S3 객체 다운로드·삭제는 탐지하지 않는다.
- **패턴 크기 제한**: 기본 2,048자이고, 할당량 증가 요청으로 4,096자까지 늘릴 수 있다. 허용 목록이 길면 규칙을 나눠야 한다.
- **공격자의 알람 삭제**: R5b로 알 수 있지만, 같은 권한이면 SNS 구독까지 지울 수 있다. 근본 대책은 계정 분리(Organizations + 위임 관리자)로, 로드맵에 넣었다.

## 10. 저장소 구조

```
aws-breach-alarms/
├─ rules/                     # 원본: 규칙 메타데이터 + 패턴 템플릿
├─ terraform/                 # 모듈 (rules/*.json을 file()+jsondecode()로 읽음)
│  └─ examples/{single-region,multi-region}/
├─ cloudformation/template.yaml        # scripts/build_cfn.py가 생성 (직접 수정 금지)
├─ scripts/build_cfn.py
├─ examples/policies/deny-outside-vpc.json
├─ tests/
│  ├─ events/<rule>/{match,nomatch}/*.json   # 가명 처리한 CloudTrail 이벤트
│  └─ ...
├─ docs/
│  ├─ design.md, design.ko.md
│  ├─ lessons-learned.md, lessons-learned.ko.md
│  └─ runbook.md          # 규칙별 대응 가이드
├─ README.md, README.ko.md, LICENSE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md
└─ .github/workflows/ci.yml
```

## 11. 테스트 전략 (TDD)

1. **패턴 테스트 (핵심)**: 규칙마다 탐지돼야 할 이벤트(match)와 걸리면 안 되는 이벤트(nomatch)를 둔다. 규칙을 고치기 전에 실패하는 테스트부터 추가한다.
   - **판정 엔진**: EventBridge가 실제로 쓰는 오픈소스 매칭 라이브러리 [`aws/event-ruler`](https://github.com/aws/event-ruler)를 CI에서 돌린다. 자격증명 없이 오프라인으로, 같은 결과를 얻는 것이 목표다.
   - **교차 검증**: 관리자는 `aws events test-event-pattern` API로 같은 테스트 데이터를 돌려 event-ruler와 결과가 같은지 확인한다(`make verify-aws`, 자격증명 필요, 무료, 리소스를 만들지 않음).
   - **테스트 데이터**: 실제 사고의 이벤트 형태를 쓰고, 계정 ID와 IP는 문서용 값으로 바꾼다.
2. **생성물 일치 테스트**: `build_cfn.py`를 다시 돌린 결과가 커밋된 `template.yaml`과 다르면 CI가 실패한다.
3. **정적 검사**: `terraform fmt -check`, `terraform validate`, `terraform test`(mock provider), `cfn-lint`, `gitleaks`
4. **배포 검증 (릴리스 전, 테스트 계정)**:
   - 규칙마다 안전한 트리거로 메일 도착을 확인한다(예: R4는 임시 IAM 사용자를 만들었다가 지움).
   - forwarder 모드의 리전 간 전달도 같이 확인한다.

## 12. 비용 (월, 작은 계정 기준)

| 항목 | 비용 |
|---|---|
| EventBridge 규칙, AWS 서비스 이벤트 수신 | 0 (AWS 서비스 이벤트는 무료) |
| 리전 간 이벤트 전달 | 매칭된 이벤트 100만 건당 약 1달러 → 사실상 0 |
| Input Transformer | 0 |
| SNS 메일 (1,000건까지) | 0 |
| SQS DLQ | 0 (프리티어 범위) |
| CloudWatch 알람 (R8 한 개당, H1) | 개당 약 0.10달러 |
| **합계** | **약 0.2~0.5달러** |

- 읽기 전용 이벤트 수신(`ALL` 상태)에도 같은 요금이 적용되는지는 릴리스 전 테스트 계정 청구서로 확인한다. 공식 문서에는 수신 요금이 따로 언급돼 있지 않다.
- CloudTrail 트레일이 없으면 하나 만들어야 한다. 관리 이벤트 첫 사본은 무료이고 S3 저장 비용만 든다.

## 13. 보안과 공개 원칙

- 저장소에 계정 ID, IP, 도메인, 회사·서비스명, 실제 역할 이름을 넣지 않는다.
- 테스트 이벤트에는 문서용 계정 ID(`123456789012`, `111122223333`)와 문서용 IP 대역(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)만 쓴다.
- CI에서 `gitleaks`를 돌리고, 공개 전에 사람이 한 번 더 검토한다.
- 생성되는 IAM 권한은 forwarder 역할의 `events:PutEvents`(홈 버스 한정) 하나다.
- `SECURITY.md`에 취약점 제보 경로를 적는다.

## 14. 버전과 기여

- 버전은 SemVer를 따른다. 규칙 추가는 minor, 패턴을 좁히거나 이름을 바꾸는 것은 major다(알림이 사라질 수 있으므로).
- 규칙을 추가할 때는 아래가 모두 있어야 한다(`CONTRIBUTING.md`).
  - `rules/<id>.json`
  - match/nomatch 테스트 이벤트
  - 런북 항목
  - CHANGELOG 항목

## 15. 결정 기록

| 번호 | 결정 | 이유 |
|---|---|---|
| D1 | Lambda를 쓰지 않는다 | 비용과 운영 부담이 0이어야 꺼지지 않는다 |
| D2 | 규칙 원본을 JSON으로 둔다 | Terraform이 그대로 읽을 수 있고 CloudFormation은 생성할 수 있다 |
| D3 | 알림은 홈 리전 하나에서만 보낸다 | 구독 확인과 관리 지점을 하나로 만든다 |
| D4 | 패턴 테스트에 event-ruler를 쓴다 | 실제 엔진과 같은 판정을 자격증명 없이 얻는다 |
| D5 | R1과 R2를 분리한다 | deny 정책이 있는 팀과 없는 팀 모두 쓸 수 있게 한다 |

## 16. 로드맵

- **v0.1**: R1~R8, H1, Terraform과 CloudFormation, home/forwarder 모드, 메일 알림
- **v0.2**:
  - AWS Chatbot으로 Slack 알림
  - 스냅샷과 S3 정밀 필터
  - 보안 그룹 `0.0.0.0/0` 개방 탐지
  - 쓰지 않는 리전에서의 활동 탐지
- **v0.3**:
  - Organizations 다중 계정: 위임 관리자 계정으로 모으기
  - (선택, 소액 비용) ALB 로그 검사 Lambda, 알림 보강 Lambda
