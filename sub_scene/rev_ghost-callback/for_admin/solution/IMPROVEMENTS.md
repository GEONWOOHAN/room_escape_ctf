# 심층 교차 검수 후 개선안

## 결론

심층 검수에서 다음 두 문제가 확인됐고, 이번 개선에서 둘 다 반영했다.

1. NFKC상 동등한 정상 exploit을 임의의 raw path 철자 하나로만 인정하는 정답 모호성
2. 96개 callback이 사실상 한 assembly template이라 parser 하나로 전부 추출되는 자동화 지점

첫 항목은 **P0 correctness 수정**, 두 번째는 플레이어와 AI의 분석 시간을 늘리는 **P1 난도 수정**으로 처리했다. 현재 남은 항목은 실행 환경 고정과 더 강한 register/basic-block 다형화다.

## 적용 상태

- 완료: raw path hash를 semantic install receipt로 교체
- 완료: U+2024, U+FE52, U+FF0E 및 percent 대소문자 동등성 회귀검증
- 완료: callback 상수 생성 6개 family 적용
- 완료: 장치마다 실제 1개와 구조가 완전한 decoy 2개 callback pointer table 적용
- 완료: 공식 solver를 pattern parser에서 격리 실행 기반 의미 복구로 교체
- 완료: 공식 solver가 원본 `for_user` 대신 임시 복사본에서 동작하도록 변경
- 보류: 고정 CPython/Unicorn 컨테이너 제공
- 보류: callback register allocation과 basic-block 순서까지 전면 다형화

## 개선 전 가장 싼 풀이

- update pipeline의 `extras/` raw 검사와 percent-decode → NFKC → C extractor 순서 차이를 찾는다.
- callback 하나에서 `encoded`, `mask`, `EOR` 형태의 상수 복구 pattern을 만든다.
- 같은 pattern으로 장치당 96개 callback의 guard, 네 상수, rotate, route term을 전부 추출한다.
- 20층×4 선택을 64비트 route target으로 meet-in-the-middle하고 세 장치 transcript를 만든다.

완성된 공식 parser의 실행은 약 7.6초다. 깊이 `4^20` 자체보다 callback 표현이 모두 같다는 점이 자동화의 핵심이다.

## 적용한 P0: raw path 철자 대신 semantic install receipt 사용

현재 flag key는 `candidate.pkg`에서 calibration과 같은 내용을 가진 optional entry의 **raw TAR path**를 찾아 hash한다. 그러나 NFKC에서 점으로 바뀌는 단일 문자는 적어도 U+2024, U+FE52, U+FF0E가 있다. 이들을 두 자리에 조합한 여러 path가 동일한 `extras/../profiles/calibration.bin`으로 변환되고 실제 덮어쓰기도 성공하지만, 출제자가 고른 fullwidth-dot 철자와 다르면 AEAD tag가 맞지 않는다.

- extractor가 성공한 뒤 semantic install receipt를 생성하게 한다.
- receipt material은 `optional entry`라는 원래 정책 class, policy stage 이후의 정규화 경로, extractor가 해석한 최종 target, 새 calibration digest를 포함한다.
- percent hex 대소문자나 NFKC 동등 문자가 달라도 같은 변환과 같은 overwrite를 만들면 같은 receipt가 나와야 한다.
- 직접 허용되지 않은 경로나 다른 target/content는 같은 receipt를 만들 수 없어야 한다.
- flag key는 raw path hash가 아니라 이 receipt를 사용한다.

오프라인 wrapper를 억지로 실행하게 만드는 것은 목표가 아니다. 정적으로 receipt를 재현하더라도 pipeline 의미를 정확히 복구해야 하게 만드는 것이 목표다.

## P0 운영 항목: 실행 환경과 release 청결성

- 지급 bytecode가 CPython 3.13·3.14 전용이므로 해당 interpreter와 Unicorn이 포함된 고정 컨테이너를 제공한다.
- 최종 archive에는 `candidate.pkg`, `events_*.json`, `callback_outputs.bin`, `.stage`, `.update_work`, runtime `__pycache__`가 없어야 한다.
- solve 실행 후 원본 handout을 압축하지 말고 allowlist staging에서 release를 만든다.

## 적용한 P1: callback codegen 6개 family

다음 표현을 callback마다 섞는다.

- PC-relative literal pool load
- ADD/SUB 분할 상수와 서로 다른 mask 결합 순서
- `ROR` 대신 shift/OR로 합성한 rotate
- register allocation과 state word 순서 교환
- basic-block 순서 변경과 의미 있는 bounded opaque branch
- terminal check와 route update의 순서 변형

각 family는 단순 byte signature가 아니라 dataflow로 같은 의미를 복구할 수 있어야 한다. 세 장치의 family 분포도 서로 다르게 한다.

## 적용한 P1: 실제 table 선택도 분석 대상으로 만들기

- callback pointer table, route target, nonce table은 각각 여러 후보 slot 중 장치별 실제 slot을 선택한다.
- callback pointer table 세 개는 모두 96개의 유효 함수 주소를 가지며, ISR이 참조하는 하나만 실제 ID mapping이다.
- nonce는 reset handler, MMIO target table은 main-loop, route target은 terminal callback의 dataflow를 따라가야 실제 후보를 고를 수 있다.
- 사용되지 않는 두 slot에도 형식이 맞는 nonce, MMIO table, 64-bit route target을 넣었다.

깊이나 branching만 키우는 것보다 parser와 dataflow 분석을 모두 요구하는 이 변경이 더 효과적이다.

## 회귀 검증 기준

- 세 종류 이상의 NFKC dot 조합과 percent-encoding 표기가 모두 같은 semantic overwrite receipt를 만들어야 한다.
- 직접 `..`, 다른 target, 다른 calibration은 거부되거나 다른 receipt를 만들어야 한다.
- callback family가 장치별로 모두 등장하고, 한 family를 지원하지 않는 reference extractor는 풀이에 실패해야 한다.
- decoy table/target도 구조적으로 완전해야 하며 단순 range·개수 heuristic으로 실제 것을 고를 수 없어야 한다.
- 최종 route는 장치마다 독립적이고 정확히 하나여야 한다.
- clean handout exact allowlist 검사를 통과해야 한다.

## 버릴 개선안

- `4^20`을 `4^24`처럼 단순 확대하는 것은 최적화된 native MITM에만 계산량을 조금 더 준다.
- `.pyc` import 차단이나 wrapper self-check는 오프라인 환경에서 지속 가능한 보안 경계가 아니다.
- exact TAR metadata나 exact event 순서를 key에 묶으면 펌웨어 분석과 무관한 정답 형식 추측이 다시 생긴다.
