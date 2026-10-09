# 심층 교차 검수 후 개선안

## 결론

심층 검수 당시 이 문제는 **P0 개선 대상**이었다. MIPS loader와 instruction semantics가 지급 Python source에 있어 핵심 역공학을 건너뛸 수 있었기 때문이다. 이번 개선에서 해당 source를 지급본에서 제거하고 semantic alias route를 추가했다. 아래의 "개선 전 가장 싼 풀이"는 과거 취약 구조를 기록한 것이다.

## 적용 상태

- 완료: 지급 Python `checker`, `loader`, `vm_runtime.py`, `crypto.py` 제거
- 완료: MIPS interpreter, payload 정책, 8-vector receipt, AEAD 검증을 stripped native PIE로 교체
- 완료: STEP마다 가시 의미가 같은 semantic alias 8개 적용
- 완료: 함수별 64비트 route 전이와 유일한 terminal route target 적용
- 완료: 여섯 repair 위치에 `8^6` 결합 판정 적용
- 완료: `FTBL360` 평문 marker 제거
- 완료: 공식 solver가 원본 지급본에 `payload.bin`을 생성하지 않도록 변경
- 보류: 함수 basic-block을 더 크게 분할하는 추가 codegen family

## 개선 전 가장 싼 풀이

- `vm_runtime.py`의 `Memory`, `load_elf`, `run_function()`을 그대로 import한다.
- `goal.pcode`가 28단계의 연산 종류, register, rotate, 상수를 정확히 알려 준다.
- 360개 함수에 공개 8-vector를 실행해 각 단계와 같은 함수를 찾는다.
- chain에서 틀린 여섯 node의 `fn_id`와 guard만 바꾼다.

즉, `target.elf`는 역공학 대상이라기보다 지급된 emulator에 넣는 데이터가 된다. 현재 다형성은 고정 offset parser는 막지만, 동적 분류에는 거의 영향을 주지 않는다.

## 적용한 P0: VM 의미 구현을 지급본에서 제거

- Python `checker`, `loader`, `vm_runtime.py`를 하나의 stripped native x86-64 checker로 합친다.
- `crypto.py`의 공개 AEAD 규격은 남겨도 된다. 난도의 핵심은 암호 형식이 아니라 MIPS 실행 의미다.
- payload header와 patch record 구조는 `for_admin/README.md` 또는 플레이어용 일반 설명에 명시해도 된다. 파일 형식 추측으로 난도를 만들 필요는 없다.
- 플레이어는 `target.elf`를 disassemble하거나 Unicorn/QEMU/custom emulator로 실행해야 한다.
- 공식 solver는 자체 MIPS 실행기 또는 일반 emulator를 사용하고, 지급 checker 내부 구현을 import하지 않는다.

## 적용한 P1: 단계별 독립 함수 lookup 제거

현재는 각 `goal.pcode` 단계에 정확히 한 함수만 대응한다. 이를 다음 구조로 바꾸는 것이 단순 함수 수 증가보다 효과적이다.

- 여섯 patch 대상 단계마다 공개 W[0..7] 전이가 같은 semantic alias를 4~8개 만든다.
- alias들은 모든 공개 vector에서 같은 W 결과를 내지만, 별도의 route accumulator를 서로 다르게 갱신한다.
- `memory.img` 또는 target 내부에 공개적으로 복구 가능한 최종 route target을 둔다.
- 여섯 위치의 alias 조합 중 하나만 최종 route target과 receipt를 만족하게 한다.
- route 전이는 가역적인 64비트 연쇄식으로 만들고, meet-in-the-middle 또는 동적 계획법으로 수십만 조합 안에서 풀리게 한다.

이렇게 하면 1단계의 함수 의미를 알아냈다고 바로 node ID가 나오지 않는다. 함수 분류와 chain 전체의 조합 분석을 모두 해야 한다.

## P2: codegen 다양화

- straight-line 연산 외에 bounded input-dependent branch, literal-pool load, basic-block 순서 변경, register permutation을 섞는다.
- 동일 semantic alias끼리도 서로 다른 family를 사용한다.
- 함수 시작 주소와 크기는 ELF table dataflow로 찾게 하되, 실행 불가능한 padding을 함수로 오인하게 만드는 무근거한 disassembly 함정은 과하게 넣지 않는다.

## 회귀 검증 기준

- 지급본에 import 가능한 `run_function`, `execute_detailed`, MIPS opcode dispatcher가 없어야 한다.
- 공식 solver가 `for_user/vm_runtime.py`나 지급 checker source를 import하지 않아야 한다.
- 각 patch 대상 단계에 공개 W 전이가 같은 후보가 최소 4개 있어야 한다.
- 각 단계만 따로 보면 후보가 유일하지 않고, 전체 route target까지 적용하면 정확히 한 조합만 남아야 한다.
- checker-only 비밀 vector 없이 모든 판정 근거를 지급 artifact에서 복구할 수 있어야 한다.
- clean handout에는 `payload.bin`과 `__pycache__`가 없어야 한다.

## 버릴 개선안

- 의미 다양성 없이 함수 수, vector 수, chain 길이만 늘리면 공식 실행 시간만 선형 증가한다.
- checker-only 비밀 vector는 플레이어가 공개 정보로 정답을 증명할 수 없게 만든다.
- Python source를 단순 `.pyc`로 바꾸는 것만으로는 decompile과 import를 잠깐 지연시킬 뿐이다.
