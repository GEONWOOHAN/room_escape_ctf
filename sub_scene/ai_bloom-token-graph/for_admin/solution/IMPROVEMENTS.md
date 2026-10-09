# 심층 교차 검수 후 개선안

## 결론

**난도 변경을 권장하지 않는다. 현재 상태를 동결한다.** 여섯 문제 중 Bloom은 이미 의도한 온라인 그래프 탐색을 실제 최단 풀이로 강제한다.

## 현재 방어가 성립하는 이유

- 한 요청은 정확히 한 5-token window만 판정한다.
- shingle마다 FNV routing으로 정해진 두 profile을 확인해야 한다.
- `allowed` 한 번 또는 routed profile 양쪽의 `blocked`가 실제 coverage에 기록돼야 한다.
- coverage가 완성되기 전 claim은 정답·오답을 같은 `incomplete` 응답으로 처리한다.
- generate와 claim이 같은 영속 2,000회 예산을 소비한다.
- 현재 128개 인스턴스의 공식 풀이 요청 수는 최소 1,619, 중앙값 1,790, p95 1,955, 최대 1,962회다.

따라서 CRC 후행 판정, 무료 claim, 한 경로만 따라가는 탐욕 풀이, 재접속 counter 초기화는 현재 코드에서 성립하지 않는다.

## `normalizer.wasm` custom section에 대한 판정

`BTG3LEX` section은 토큰-ID mapping을 쉽게 주지만, 이것을 숨기는 변경은 핵심 난도를 거의 높이지 않는다. 토큰 문자열은 `vocab.txt`에 있고 normalizer 자체도 로컬 실행·분석할 수 있어 mapping 복구가 짧은 전처리로 끝난다. 이 section 제거를 난도 개선 P0/P1으로 분류하지 않는다.

## 유지할 운영 불변식

- 팀이 처음 접속할 때 인스턴스를 한 번 배정하고, 이후 재접속에서도 같은 seed를 사용한다.
- counter, instance index, shingle/profile coverage를 같은 팀 namespace에 영속화한다.
- consume와 coverage 기록은 transaction으로 직렬화한다.
- coverage 전 claim의 응답 key와 형태는 payload 정오에 따라 달라지지 않게 유지한다.
- 배포 전 전체 seed pool을 공식 solver로 다시 검사하고 2,000회를 넘는 seed는 배포하지 않는다.

## 하지 않을 변경

- 요청 제한을 더 낮추지 않는다. 현재 최악 seed는 38회 여유뿐이라 난도보다 네트워크 상태를 평가하게 된다.
- 접속마다 seed를 바꾸지 않는다. 영속 coverage가 서로 다른 그래프를 가리켜 정상 풀이가 망가진다.
- CRC를 다시 정답 엔트로피나 후행 오라클로 넣지 않는다.
- prompt grouping을 허용하지 않는다. 경계에서 추가 5-token window가 생기는 현재 제약을 유지한다.
- 단순 lexicon 난독화나 WASM codegen family 추가는 이번 강화 범위에서 제외한다.

## 회귀 검증 기준

- 128개 이상 seed에서 공식 풀이가 2,000회 이내이고 coverage가 정확히 완성돼야 한다.
- coverage 전 올바른 payload와 틀린 payload의 claim 응답이 동일해야 한다.
- 동시 요청과 재접속 후에도 counter가 감소하거나 중복 소비를 우회할 수 없어야 한다.
- 한 요청으로 두 개 이상의 의도한 shingle을 판정할 수 없어야 한다.
- 최종 handout에 server secret, team token, instance payload, solve 산출물이 없어야 한다.

현재 회귀는 동일 팀 200개 동시 요청의 counter 연속성과 128개 전체 seed 풀이를 함께 검사한다. 배포 컨테이너에는 90개 팀 토큰을 동시에 접속시켜 오류 0건, 인스턴스 중복 0건, 초기 counter 0을 확인했다. 난도 수치가 그대로 유지되므로 추가 알고리즘 변경은 하지 않았다.
