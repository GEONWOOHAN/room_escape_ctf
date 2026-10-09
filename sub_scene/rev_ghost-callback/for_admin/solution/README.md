# 공식 풀이 및 검증

## Flag

`SHA{one_semantic_policy_wakes_the_entire_ghost_fleet}`

검수 실행에는 CPython 3.13 또는 3.14와 Capstone이 필요하다. 지급 `device_runner`와 `updater`는 두 버전의 사전 컴파일 bytecode를 선택하며 Unicorn은 `vendor/`에 포함되어 있다.

## 1. 업데이트 경계 우회

서명된 manifest는 세 펌웨어와 원래 calibration의 raw TAR 경로·해시만 검증한다. 다음 단계는 URL percent decoding 후 NFKC를 적용하고, C extractor는 그 결과에서 `..`를 다시 정규화한다.

직접 `%2e%2e`는 중간 검사에서 거부된다. 공식 풀이는 `extras/` 아래에 percent-encoded fullwidth dot 두 개를 넣어 raw 검사를 통과한 뒤 NFKC에서 부모 경로로 바뀌게 한다. 이 엔트리가 서명된 calibration을 generation 18 값으로 덮는다.

## 2. 콜백 그래프와 결합 상태 복구

각 64 KiB ARM Thumb 펌웨어에는 96개의 유효 Thumb 주소로 이루어진 포인터 테이블이 세 개 있다. 세 테이블 모두 주소 범위·개수·함수 prologue 검사를 통과하고, 두 개는 callback ID를 다르게 섞은 완전한 decoy다. vector table에서 ISR을 찾고 ISR의 dataflow가 참조하는 테이블만 실제 ID mapping으로 사용한다.

콜백은 고정 stride가 아니며 의미 상수도 한 패턴으로 만들어지지 않는다. callback마다 다음 여섯 family 중 하나가 선택된다.

- XOR mask 두 항 복원
- ADD split
- SUB split
- rotate 전후 변환
- bitwise NOT
- rotate와 XOR mask 결합

공식 풀이는 이 여섯 문법을 signature로 각각 파싱하지 않는다. callback을 격리된 Unicorn 인스턴스에서 실행하고 첫 guard 비교 시점의 register를 관측한 뒤, 세 개의 route 입력에 대한 출력으로 회전량과 term을 역산한다. 따라서 새 family가 추가돼도 callback의 의미가 같으면 solver를 다시 byte-pattern에 맞출 필요가 없다. 다음 값을 복구한다.

- 입력 guard
- 다음 guard
- 두 개의 32비트 route term과 두 회전량
- 레지스터 변환 상수와 회전량

guard graph에는 20개 layer가 있고 각 layer에 같은 다음 guard를 향하는 4개 콜백이 있다. 각 선택은 두 상태 워드를 순서 의존적으로 갱신한다.

```text
a' = ROR32(a XOR term0, rot0) + b
b' = ROR32(b XOR term1, rot1) + a'
```

이 전이는 역산할 수 있다. 앞 10단계의 `4^10` 상태를 저장하고 최종 상태에서 뒤 10단계를 역방향으로 탐색하면 장치당 약 `2 × 4^10` leaf로 유일한 체인을 찾는다. 전체 경로 공간은 `4^20 = 1,099,511,627,776`이고, 세 장치는 서로 다른 선택 벡터를 사용하므로 한 장치의 분기 번호를 재사용할 수 없다.

세 장치의 선택된 콜백 ID, 전후 guard, 두 route term·회전량과 두 route target 워드를 `device.json`의 규칙대로 직렬화한다. 이 route proof의 BLAKE2s digest를 반으로 나눈 값이 MMIO seed와 permutation seed다. 따라서 관리자 전용 상수 없이 지급본 분석 결과만으로 generation 18 calibration 전체를 재구성할 수 있다.

## 3. 이벤트 및 플래그

calibration의 permutation seed로 96채널 Fisher-Yates 배열을 재현하고, 각 펌웨어의 target table과 MMIO window 식을 역산해 `events_a.json`~`events_c.json`을 만든다. `device_runner`가 세 장치를 실행하면 장치당 160바이트 transcript가 `callback_outputs.bin`에 기록된다. 지급 runner에는 콜백 ID나 guard를 돌려주는 디버그 trace가 없다.

업데이트 pipeline은 최종 calibration write에 대해 source policy class, NFKC 이후 경로, extractor가 해석한 최종 target과 내용 digest를 결합한 semantic install receipt를 `.stage/.install_receipt`에 기록한다. U+2024, U+FE52, U+FF0E의 조합이나 percent hex 대소문자가 달라도 같은 overwrite 의미라면 receipt가 같다. 직접 `..`, 다른 target, 다른 내용은 같은 receipt를 만들 수 없다.

semantic install receipt, calibration digest, 세 펌웨어 digest와 세 transcript를 결합한 BLAKE2s 키로 `flag.enc`의 ChaCha20-Poly1305 tag를 검증한다. TAR metadata나 동등한 path 철자, 같은 콜백을 깨우는 여러 event schedule 중 하나를 임의 정답으로 강제하지 않는다.

## 실행

```bash
python3 for_admin/solution/solver/solve.py
```

위 명령은 `for_admin/solution/`의 공식 검수 환경을
기준으로 한다. 솔버는 현재 작업 디렉터리의 공개 파일과 지급 `vendor/`만 읽고,
`for_admin`의 생성기·패키지 빌더·암호 모듈을 사용하지 않는다. 실행 중 필요한
패키지와 이벤트 파일은 임시 지급본 사본에만 생성된다.

13단계 회귀 테스트가 서명 변조, 네 required object 변조, 직접 traversal, 18가지 NFKC/percent 동등 path의 receipt 일치, 잘못된 분기, 무작위 transcript, 세 포인터 테이블과 ISR 선택, 여섯 codegen family, 구형 mask parser의 부분 실패, 결합 상태 가역성, 장치별 독립 경로, 공개 trace 제거, 정답 레시피·평문 누출과 clean release allowlist를 검사한다. 빌드와 테스트는 `for_admin/.build/for_user/`에서만 이루어지며, 공식 solver의 command-line 진입점도 입력 지급본의 임시 복사본에서 동작한다. 실제 `for_user/`를 교체하는 동작은 `make release`에만 있다.
