# 공식 풀이 및 검증

## Flag

`SHA{cross_backend_pcode_refinement_requires_real_execution}`

## 풀이 흐름

1. `target.elf`의 program header와 `fn_table`을 복구해 가변 위치에 뒤섞인 360개 MIPS32 함수 주소를 얻는다. ID 기반 고정 stride 계산은 성립하지 않는다.
2. `goal.pcode`의 28개 STEP을 파싱한다. 각 STEP은 ARX, zero/sign extension, partial-byte store가 섞인 두 연산으로 구성된다.
3. `vectors.bin`의 8개 입력에 대해 각 후보 함수를 실제 MIPS 명령 의미로 실행한다. 함수마다 register allocation, state/argument pointer bias, load 순서, 직접 ROTR 또는 shift+OR 합성, `lh/lhu` 또는 명시적 extension, dead branch store와 scratch store가 달라진다. 고정 instruction field를 tuple로 읽는 파서는 사용할 수 없다.
4. 각 STEP과 가시 W[0..7] 전이가 같은 함수가 정확히 8개씩 남는다. 이전처럼 여기서 함수 ID가 하나로 결정되지 않는다.
5. `memory.img`에서 guard 식이 맞는 비연속 28개 힙 노드 체인을 찾는다. 여섯 노드만 가시 의미가 틀린 미끼 함수이므로 repair 위치는 결정적으로 식별된다.
6. semantic alias 함수들을 서로 다른 세 route 입력으로 실행한다. 함수가 숨은 두 word에 적용하는 `term0`, `term1`, 두 rotate를 역산한다.
7. 정상 22개 node는 현재 ID를 유지하고, 여섯 repair 위치에서 각각 8개 alias를 선택한다. `8^6 = 262,144`개 route 조합 중 `memory.img`의 terminal 64-bit target과 같은 유일한 체인을 고른다.
8. 시작 포인터와 argument bias를 고치는 `ABS32` 두 개, 잘못된 여섯 node의 함수 ID와 guard를 고치는 `HEAP32` 열두 개를 만들어 총 14개 record를 채운다.
9. stripped native checker는 여덟 vector에서 각 단계의 함수 ID, node 좌표, 전후 W 상태와 route 상태를 receipt에 넣는다. 최종 32바이트 W만 계산하거나 가시 의미가 같은 임의 alias를 고르면 암호 키가 만들어지지 않는다.

## 실행

```bash
python3 for_admin/solution/solve_reference.py
```

위 명령은 `for_admin/solution/`의 공식 검수 환경을
기준으로 한다. `solve_reference.py`의 여섯 교체 지점과 함수 ID는 공개
`target.elf`, `memory.img`, `goal.pcode`, `vectors.bin`을 분석해 얻은 결과다.
솔버는 관리자용 `config.py`나 `vm_runtime.py`를 import하지 않고, 임시 지급본
사본에 payload를 만든 뒤 공개 native checker로만 검증한다. 따라서 원본
`for_user`에는 `payload.bin`이 생기지 않는다.

검증은 템플릿 실패, 정답 성공, 1비트 변조, 잘린 payload, 금지 주소 쓰기, memory/flag 결합, 가변 함수·node 배치, 다형 함수 구조, 단계별 8개 alias, 유일한 64비트 terminal route, 결과 직계산 방지, stripped native PIE, 지급 VM source 부재, ChaCha20-Poly1305 상호운용과 정확한 7파일 지급본 whitelist를 확인한다.
