# No Stack, Still Turing

## 의뢰서

**의뢰 이름:** 폐기 단말의 p-code 실행 체인 복구

**의뢰인:** `JUNKMAN_0xDEAD!`

**의뢰 내용:**

고철값으로 넘기려던 단말인데, 안에 뭔가 남았습니다. 스택은 막혔고 아무 데나 쓰지도 못합니다. 대신 힙의 디스패치 노드하고 함수 번호는 건드릴 수 있더군요.

`goal.pcode`와 MIPS32 실행 파일, 메모리 이미지를 첨부했습니다. 360개 함수 중 올바른 상태 전이를 골라 **28단계 체인**을 복구하고, 허용된 14개 패치 레코드만으로 여덟 입력 벡터를 모두 통과시켜 주세요. 같은 p-code 결과를 내는 함수도 여러 개라 마지막 route receipt까지 맞춰야 합니다.

마지막 숫자만 맞추는 요령은 안 통합니다. 지나간 길까지 영수증에 찍힌답니다. 기록을 꺼내 오면 고철값보다야 후하게 쳐 드리죠.

## 운영 정보

- 유형: 오프라인 MIPS32·p-code·제한 쓰기 합성
- 플레이어 지급본: `for_user/`
- 함수 수: 360개
- 단계별 semantic alias: 공개 W 전이가 같은 함수 8개
- 체인 길이: 28단계
- 입력 검증: 8개 벡터
- 쓰기 제한: `ABS32` 2개 + `HEAP32` 12개
- 키 파생: 각 단계의 함수 ID·노드·전후 W 상태와 숨은 64비트 route 상태를 포함한 canonical receipt
- 무결성 결합: `target.elf`, `memory.img`, `vectors.bin` digest
- 배치: 함수 주소와 28개 heap node 위치 모두 가변·비연속
- 코드 다형성: 함수별 register allocation, pointer bias, load 순서, extension·rotate 구현 및 dead/scratch store 변화
- 플래그 형식: `SHA{...}`
- 지급 checker: Python source가 없는 stripped Linux x86-64 PIE

```bash
make build
make verify
make solve
make release
```

`make build`는 `for_admin/.build/for_user/`에만 결과를 만들고, `make verify`는 그 관리자 빌드의 임시 복사본에서 checker를 실행한다. `make solve`는 현재 지급본을 읽지만 `payload.bin`은 임시 디렉터리에만 놓는다. 실제 `for_user/`를 교체하는 명령은 검수 후 사용하는 `make release`뿐이다.

빌드에는 GCC와 OpenSSL `libcrypto` 개발 파일이 필요하다. 플레이어 지급 checker도 Linux x86-64의 `libcrypto`를 동적 사용한다.

지급본에는 더 이상 `vm_runtime.py`, Python `checker`, `loader`, `crypto.py`가 없다. 플레이어는 `target.elf`를 직접 disassemble하거나 일반 MIPS emulator용 harness를 작성해야 한다. 가시 W 전이만 비교하면 단계마다 8개 후보가 남고, 틀린 여섯 node의 `8^6` 조합은 각 함수가 갱신하는 숨은 route 전이와 terminal target으로 판정한다. 공식 풀이기는 `solution/solve_reference.py`이며 원본 `for_user`에 `payload.bin`을 만들지 않는다.
