# 심층 교차 검수 후 개선안

## 적용 결과

P0 answer-sheet schema와 `layoutgen` 계산기 인터페이스를 제거했다. 아래 첫 절은 수정 전 가장 싼 풀이를 남긴 기록이며 현재 지급본에서는 재현되지 않는다.

## 현재 가장 싼 풀이

`schema.wasm`의 `schema` custom section은 `VCFG`, 1바이트 XOR key, JSON으로 구성된다. 복호화하면 다음 항목이 그대로 나온다.

- payload alphabet과 길이, CRC
- canonical layout 번호
- bucket size 16
- fixed-Huffman DEFLATE와 JSON serialization
- 정확한 probe prefix
- 각 16-request epoch가 0..15의 비밀 permutation이라는 규칙
- epoch 경계에서 16개를 더하라는 정확한 stable score

`layoutgen`도 임의의 `counter seed style`을 받아 정확한 `layout/cover`를 출력한다. 공식 solver는 schema를 읽고 안전한 seed를 고른 뒤 후보마다 16회를 더한다. 현재 6,928회라는 수치는 분석 난도가 아니라 이 기계적 측정 횟수다.

## 적용 완료: 스키마를 설명서가 아니라 단서로 바꾸기

- flag alphabet, payload 길이, CRC, API 형식은 공개해도 된다.
- `canonical_layout`, 정확한 bucket 크기, secret permutation 문장, `stable_score` 공식은 제거한다.
- 압축 export라는 사실은 남기되 내부 JSON record 순서와 정답 record 위치를 그대로 적지 않는다.
- 대신 알려진 note를 여러 counter에서 export한 짧은 calibration transcript를 제공한다. 반복성과 균형성은 관측으로 추론할 수 있어야 하지만, "16개를 합하라"는 문장은 없어야 한다.
- `schema.wasm` custom section의 1바이트 XOR JSON은 제거하고, 필요한 최소 설정만 여러 export 동작 또는 실제 client dataflow에서 복구하게 한다.

## 적용 완료: `layoutgen` 계산기 인터페이스 제거

- 임의 입력의 `layout/cover`를 출력하는 CLI를 지급하지 않는다.
- stripped object나 client module 안에 실제 selector를 포함하고, 고정 self-test만 외부로 노출한다.
- 공식 solver는 역공학으로 복구한 selector를 독립 구현해야 한다.
- selector family를 style별로 3~4개 사용하면 한 xorshift 식을 옮겨 전체 counter를 처리하는 자동화도 막을 수 있다.

## 보류: 후보별 16연속 합산을 한 단계 더 결합

스키마만 숨기면 규칙을 한 번 알아낸 뒤 기존 loop가 그대로 남는다. 더 강화하려면 다음 실험안을 검토한다.

- 같은 probe class는 한 epoch에서 한 번만 유효 측정되게 한다. 문자열 뒤에 무의미한 장식을 붙여 rate limit을 우회하지 못하도록 실제 recovery prefix를 canonicalize한 class를 사용한다.
- padding은 `team || probe_class || super-epoch`으로 만든 16개 균형 순열에서 선택한다.
- 한 후보가 16개 noise 값을 모두 경험하려면 여러 epoch에 걸쳐 측정해야 하며, 한 epoch에서는 16개 다음 문자 후보를 서로 교차 배치하게 한다.
- 총 요청량은 현재의 후보당 16회와 비슷하게 유지하되, solver가 counter scheduling과 균형 행렬을 먼저 복구하게 한다.

이 안은 상태 추적과 우회 가능성이 있으므로 바로 적용하지 말고 adversarial solver로 먼저 검증해야 한다. P0 두 항목만 적용해도 현재보다 분석 비중은 크게 올라간다.

현재 `schema.wasm`은 JSON이나 단일-byte XOR 설정을 포함하지 않는다. 최소 flag 문법과 64개 binary calibration observation만 서로 다른 custom section에 둔다. release `layoutgen`은 stdin과 무관한 고정 self-test만 내며, counter에 따라 네 전이 family가 바뀐다. 공식 solver는 size 공약수·반복 구간 합·표본 layout 일관성을 직접 추론하고 native 바이너리를 호출하지 않는다. P1은 온라인 상태 복잡도와 우회면을 크게 늘리므로 이번 적용에서 제외했다.

공통 prefix 전체, `SHA{...}` 부분, payload 부분만 각각 8개 후보씩 한 note에 넣는 반분 template을 모든 payload 위치에서 검사했으며 어느 template도 전체 위치를 판별하지 못했다. 같은 후보를 1·2·4·8·16회 반복해도 정확한 압축 길이 spread가 최대 2바이트여서 16바이트 bucket과 비밀 padding을 단일 측정으로 넘지 못한다. 이 회귀는 알려진 대표 template에 대한 방어선이지 임의의 모든 압축 template에 대한 수학적 증명은 아니다.

## 반드시 추가할 공격 회귀검증

- 한 note 안에 여러 다음 문자 후보를 함께 넣는 subset/group-testing template을 탐색한다.
- 동일 후보를 1~16회 반복해 압축 차이를 증폭하는 template을 탐색한다.
- delimiter, 후보 순서, filler, style, non-canonical layout을 바꾼 자동 optimizer를 돌린다.
- 공식 per-character 풀이보다 현저히 적은 요청으로 후보 집합을 나누는 template이 나오면 생성 규칙을 다시 조정한다.
- 64개 이상 무작위 운영 flag에서 유일 복구와 16,000회 상한을 다시 확인한다.

## 버릴 개선안

- flag 길이만 늘리면 같은 loop 횟수만 증가한다.
- 독립 난수 padding이나 네트워크 timing noise는 재현성과 팀 간 공정성을 해친다.
- custom section의 XOR key만 복잡하게 만드는 것은 몇 분짜리 난독화일 뿐이다.
- 요청 예산을 공식 solver 최대치 가까이 낮추는 것은 분석력이 아니라 네트워크 운을 평가한다.
