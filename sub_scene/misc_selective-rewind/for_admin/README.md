# Selective State Rewind

## 의뢰서

**의뢰 이름:** 세 증거 서버의 관리자 상태 복구

**의뢰인:** `AUDIT#07`

**의뢰 내용:**

증거 서버 세 대. 같은 프로그램. 전부 로그인 실패.

다만 캐시에는 실패 직전 상태가 남아 있습니다. 각 이미지에서 dirty line을 정확히 다섯 번 버리면 관리자 세션과 이전 generation, 남은 lease, 감사 기록을 되살릴 수 있을 겁니다. 메모리 배치와 시점은 세 대가 모두 다르고, 정상 trace에서는 주소와 PC가 지워져 있습니다.

세 대 전부 성공해야 합니다. 부분 성공은 증거가 아닙니다.

## 운영 정보

- 유형: 오프라인 커스텀 VM·캐시 상태 분석
- 플레이어 지급본: `for_user/`
- 이미지: `image_a`, `image_b`, `image_c`
- 규모: 이미지당 약 11,500~11,800 명령, 수백 개 이상의 관련 dirty 후보
- 정답 조건: 이미지당 서로 다른 5개 fault, 총 15개 모두 필요
- 플래그 키: 세 canonical plan과 세 최종 상태 digest 결합
- 플래그 형식: `SHA{...}`
- 지급 VM: Linux x86-64 정적 ELF, 런타임 디버그/trace oracle 없음
- replay 응답: 모든 정상 형식 오답은 동일한 `{"success":false}`만 반환하고 digest를 만들지 않음
- 봉인 규격: `for_user/manifest.json`의 `flag_seal`에 KDF·canonical plan·AEAD 형식을 공개

```bash
make build generate
make test
make release
```

VM, 세 이미지와 테스트 실행물은 모두 `for_admin/.build/for_user/`에서 생성된다. 일반 빌드·생성·테스트·정리 명령은 실제 지급본을 수정하지 않는다. 검수가 끝난 관리자 빌드를 실제 `for_user/`로 복사하는 명령은 `make release`뿐이다.

`trace.map`과 VM 내부 디버그 채널은 배포하지 않는다. 각 이미지의 `bus.trace`는 256개 명령 단위 opcode histogram과 양자화된 dirty transition만 담으며 정확한 좌표를 제거한 관측치다. 정답과 동일한 지역 opcode 형태와 과거 정답 레지스터 조합은 역방향 slice 안에도 대량의 camouflage로 존재하므로 선형 시그니처 검색은 답을 고르지 못한다. 정상 형식의 오답끼리는 종료 코드, stdout/stderr, 결과 JSON, digest 존재 여부가 모두 같아야 한다. 정답을 구한 플레이어가 관리자 자료 없이도 복호화를 구현할 수 있도록 봉인 규격만 manifest에 명시한다. 공식 풀이와 검증 방식은 `solution/README.md`에 있다.
