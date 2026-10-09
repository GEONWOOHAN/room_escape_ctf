# Ghost Callback

## 의뢰서

**의뢰 이름:** 세 센서 펌웨어의 숨은 콜백 체인 실행

**의뢰인:** `S0LDER.GUN_9`

**의뢰 내용:**

센서 세 대를 뜯어 왔습니다. 펌웨어 서명은 멀쩡합니다. 그쪽을 깨려 하지 마세요. 대신 업데이트를 풀 때마다 경로를 해석하는 순서가 묘하게 다릅니다. 보정 파일 하나 정도는 끼워 넣을 틈이 있어 보여요.

각 펌웨어에는 주소가 뒤섞인 콜백 96개가 있고, 20단계마다 후보가 네 개씩 열립니다. 이벤트 순서를 맞춰 진짜 콜백 체인을 깨우고 세 장치의 실행 기록을 전부 가져오세요. 단순한 `%2e%2e` 경로 장난은 이미 막혀 있습니다.

세 대가 전부 같은 보정 파일을 먹고 움직였다는 기록까지 가져오세요. 한 대만 켜 온 건 고장 확인이지, 일이 아닙니다.

## 운영 정보

- 유형: 오프라인 펌웨어·업데이트 파이프라인·MMIO 에뮬레이션
- 플레이어 지급본: `for_user/`
- 펌웨어: `firmware_a.bin`, `firmware_b.bin`, `firmware_c.bin`
- 콜백 그래프: 장치당 20단계 × 4분기 = 1,099,511,627,776 경로
- 배치: 고정 stride 없음, 구조가 완전한 포인터 테이블 3개 중 ISR이 실제 테이블 하나를 선택
- 콜백 표현: XOR mask, ADD/SUB split, rotate, NOT 등 6개 codegen family
- 경로 판정: 순서에 민감한 두 개의 결합된 32비트 상태
- 정답 출력: 장치당 160바이트 transcript 세 개
- 플래그 형식: `SHA{...}`
- 지급 실행 환경: Linux x86-64, 빌드 시 함께 생성된 CPython bytecode 버전 중 하나

```bash
make build
make test
make release
```

`make build`와 `make test`는 `for_admin/.build/for_user/`만 사용한다. 테스트가 만드는 공격 패키지, 설치 stage, 이벤트와 callback 출력도 이 관리자 작업 공간 안에만 생긴다. 실제 `for_user/`는 검수 후 명시적으로 `make release`를 실행할 때만 관리자 빌드의 복사본으로 교체된다. `make clean` 역시 관리자 빌드와 캐시만 지우며 지급본을 건드리지 않는다.

빌드는 설치되어 있는 CPython 3.11~3.14용 bytecode를 함께 생성하고 실행기가 호환 버전을 자동 선택한다. calibration의 32바이트 seed는 비밀 상수가 아니라 세 펌웨어에서 복구한 route proof 전체의 BLAKE2s digest로 결정된다. 정확한 proof 직렬화 형식만 지급본 `device.json`에 공개하며, 경로 우회 문자열이나 이벤트 정답은 공개하지 않는다.

업데이트 성공 시 raw TAR 철자가 아니라 `optional 정책 class + NFKC 이후 경로 + extractor 최종 경로 + calibration digest`로 semantic install receipt를 만든다. 따라서 같은 overwrite를 만드는 NFKC 동등 문자는 모두 같은 정답으로 인정된다. 관리자 공식 solver는 원본 `for_user`가 아니라 임시 복사본에서만 실행되어 지급본에 `candidate.pkg`, 정답 이벤트, `.stage`, callback 출력이 남지 않는다. 풀이 과정은 `solution/README.md`에 있다.
