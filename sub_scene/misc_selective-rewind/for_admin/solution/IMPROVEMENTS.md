# 심층 교차 검수 후 개선안

## 적용 결과

P0 차분 오라클과 배포 오염 문제를 수정했다. 아래 첫 절은 수정 전 취약 동작을 남긴 검수 기록이며, 현재 release에서는 재현되지 않는다.

## 확인된 언인텐 풀이

`apply_fault()`는 선택한 line이 없거나 dirty가 아니면 아무 동작도 하지 않는다. 반면 유효한 5-fault plan이 실행되면 성공 여부와 관계없이 다음 값이 모두 지급된다.

- `halted`
- `authenticated`, `uid`, `generation`, `reason`, `lease`
- `audit_valid`, `faults_consumed`, `success`
- 전체 논리 메모리 snapshot의 SHA-256인 `final_state.digest`

따라서 한 개의 후보 fault와 네 개의 clean/absent line no-op을 조합해 후보 하나만 바꿔 볼 수 있다. 정책 필드는 JSON 차이로, 필드에 바로 드러나지 않는 변화는 256비트 digest 차이로 판정할 수 있다. VM ISA와 cache 의미를 완전히 복구하지 않아도 각 정답 지점을 독립적으로 스캔하는 로컬 오라클이 된다.

검수 시점의 지급 디렉터리에도 `image_a/plan.json`, `result.json`, `final_state.digest`가 생성돼 있었고, 한 후보와 네 no-op을 넣은 실패 plan에도 상세 필드와 digest가 기록됐다. 현재 생성기는 이 파일을 배포하지 않고, 공식 solver도 임시 handout 사본 안에서만 산출물을 만든다.

## 적용 완료: 모든 실패를 같은 관측으로 만들기

- 문법상 유효한 plan이 실패하면 `result.json`은 항상 동일한 `{"success":false}`만 기록한다.
- 실패 시 `final_state.digest`를 만들지 않는다.
- 성공한 정확한 plan에만 `{"success":true}`와 `final_state.digest`를 기록한다.
- 실패 종류에 따라 stdout, stderr, 종료 코드, 파일 존재 여부가 달라지지 않게 한다. malformed input과 내부 파일 손상은 별도 오류여도 되지만, 정상 형식의 오답 plan끼리는 구분되면 안 된다.
- partial policy field나 snapshot digest는 VM 내부 계산과 관리자 테스트에서만 사용한다.

성공/실패 1비트 자체는 로컬 checker의 목적상 피할 수 없다. 중요한 점은 서로 다른 오답 사이에 추가 정보가 없어야 한다는 것이다.

## 적용 완료: 배포 산출물 차단

- release 직전 `plan.json`, `result.json`, `final_state.digest`, `fleet_plan.json`, `solution.report.json`을 제거한다.
- 테스트 후 작업 디렉터리를 그대로 압축하지 말고 깨끗한 staging 디렉터리에 allowlist 파일만 복사한다.
- 세 이미지에는 `program.bin`, `initial_state.bin`, `bus.trace`, `plan.template.json`만 허용한다.

## 보류: 역공학 뒤의 로컬 1-fault 분류 결합

- 두 정책 값이 함께 보존되어야만 후속 계산이 정상화되도록 dependency를 결합한다.
- 단일 fault는 최종 결과에 독립적인 유용 신호를 남기지 않고, 제한된 pair search 또는 단계적 beam search가 필요하게 한다.
- 의존 쌍, cache line mapping, opcode encoding family를 이미지마다 바꾼다.
- 다만 최종 조합은 backwards slice와 cache simulation으로 결정적으로 구할 수 있어야 하며, 무작위 조합 폭발에 의존하면 안 된다.

## 회귀 검증 기준

- canonical plan의 fault 하나를 교체한 모든 경우가 byte-for-byte 동일한 실패 출력을 내야 한다.
- 실제 후보 하나와 실행되지 않는 네 filler를 섞은 plan 및 무작위 plan 수백 개가 같은 종료 코드와 같은 `result.json`을 만들고 digest를 남기지 않아야 한다.
- 임의의 유효한 5-fault plan들도 오답끼리 구분되지 않아야 한다.
- 정확한 plan만 digest를 생성하고 세 이미지 receipt로 flag를 복호화해야 한다.
- 최종 handout 파일 목록을 exact allowlist로 검사해야 한다.

현재 자동 테스트가 위 기준을 모두 검사한다. P1의 정책 의존성 결합은 정적 인과 분석까지 무의미하게 만들 위험과 풀이 조합 폭발의 비용이 더 커서 이번 적용에서는 제외했다. 배포 checker에서 얻는 정보는 성공 1비트뿐이며, 풀이의 중심은 세 바이너리의 ISA·cache·data-flow를 복구하는 작업으로 유지했다.

## 버릴 개선안

- fault 수만 늘리면 문제 분석이 아니라 조합 수만 커진다.
- dirty line 여부를 별도 오류로 알려 주면 그것도 새로운 후보 판정 오라클이 된다.
- 손실형 `bus.trace`까지 제거하면 근거 있는 역분석 단서가 사라진다.
- anti-debug나 self-integrity는 오프라인 바이너리에서 지속 가능한 보안 경계가 아니다.
