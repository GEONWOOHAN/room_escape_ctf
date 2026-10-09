# 공식 풀이 및 검증

## Flag

`SHA{9e4d3a2520e58dfddd34fff749d77ca4}`

## 풀이 흐름

각 이미지의 `program.bin`은 16바이트 고정 폭 명령을 가진 커스텀 VM이다. `replay_vm`을 역공학해 LOAD, STORE, FLUSH, MEMCPY, HASHSTEP, HALT와 32-line write-back cache의 동작을 복구한다.

HALT가 참조하는 56바이트 결과 객체에서 역방향 qword taint slice를 만들고, 정상 실행 중 관련 line이 dirty인 checkpoint를 수집한다. 강화 생성기는 값 변경 뒤 XOR 영값을 거쳐 원래 값을 복원하는 데이터 흐름과 `MEMCPY→HASHSTEP` 흐름을 slice 안에 대량 삽입한다. 따라서 `MOVI→STORE→LOAD`, 고정된 r0/r1, 또는 `MEMCPY→HASHSTEP` 인접성만 검색하면 수십~수백 개의 가짜 좌표가 나온다.

정답 다섯 지점은 배포 `replay_vm`의 오답 응답을 관찰해서 식별할 수 없다. 정상 형식의 모든 오답은 byte-for-byte 같은 `{"success":false}`만 남기고 `final_state.digest`를 생성하지 않는다. 따라서 ISA와 cache를 복구한 뒤, 플레이어가 작성한 로컬 모델 안에서 후보 직후 cache line을 실제로 폐기하며 다음 인과 관계를 추적해야 한다.

1. 이전 authenticated 값을 새 실패 값 대신 보존하는 STORE 직후
2. 이전 uid를 두 번의 복사 전에 보존하는 STORE 직후
3. 이전 generation을 effective map으로 읽기 직전
4. lease 소비 값을 읽기 직전
5. 실패 audit prefix를 256비트 상태에 덮은 MEMCPY 직후

풀이 분석에서는 독립 disassembler와 cache 동작을 작성해 write 후보를 하나씩 replay했다. 최종 정책 객체의 `(authenticated, uid, generation, reason, lease)` 중 정상 실패값을 정확한 보호값으로 바꾸는 네 좌표를 찾고, 그 네 좌표를 고정한 뒤 남은 후보 중 audit까지 성립시키는 한 좌표를 찾는다. 이는 지급 checker의 상세 실패값을 쓰는 풀이가 아니다. camouflage는 정적 taint에는 남지만 실행 결과를 대수적으로 원복하므로 로컬 인과 검사에서 제거된다. 다섯 개 중 하나라도 빼거나 이웃 checkpoint·다른 line을 쓰면 성공하지 않는다. `solver/solve.py`는 이 분석으로 확정한 세 plan을 공개 native VM에서 재검증하고 플래그를 복호화하는 최종 재현 코드다.

이 분석을 `image_a`, `image_b`, `image_c`에 각각 수행해 서로 다른 plan 세 개를 만든다. 각 완성 plan만 native `replay_vm`에 한 번 제출한다. 성공할 때만 생성되는 최종 상태 digest와 canonical plan 세 쌍을 결합한 키만 `flag.enc`를 복호화한다.

플레이어가 최종 정답을 얻은 뒤 봉인 형식을 추측해야 하는 상황은 의도하지 않는다. KDF의 domain, 이미지 순서, `PLN3` 레코드 인코딩, AES-GCM AAD는 지급본 `manifest.json`의 `flag_seal`에 공개되어 있다. 반면 과거 VM에 있던 `debug.cfg` 기반 PC·cache 로그 기능은 풀이 단계를 우회하므로 지급 바이너리와 소스에서 제거했다.

## 실행

```bash
python3 for_admin/solution/solver/solve.py
```

위 명령은 `for_admin/solution/`의 공식 검수 환경을 기준으로 한다. 공식 solver는 각 이미지의 공개 파일과 `replay_vm`, `flag.enc`만 사용한다. `plan.json`, `result.json`, digest는 이미지별 임시 디렉터리에만 생성되므로 원본 handout에는 풀이 산출물이 남지 않는다.

회귀 테스트는 4-of-5 부분해, 이미지 간 좌표 복사, 인접 checkpoint, 잘못된 line, native/Python 성공 동치, 수백 개의 격리·무작위 오답 관측 동일성, parser 혼동, stale receipt 제거, 공개 봉인 규격, 공식 solver 비오염성, 디버그 oracle 부재, 지급본 exact allowlist와 지역 opcode 시그니처의 비유일성을 검사한다.
