# 공식 풀이 및 검증

## Flag

정적 플래그: `SHA{a1b2c3d4e5f6-90d2}`

운영 배포에서도 같은 정적 플래그를 사용한다.

## 풀이 흐름

1. `schema.wasm`의 `public`과 `samples` custom section을 파싱한다. `public`에는 flag alphabet·payload 길이·CRC 식별자·형식만 있고, `samples`에는 같은 알려진 note로 수집한 64개 `(counter, seed, style, filler, size)` 관측이 있다.
2. 표본 size들의 최대공약수로 16-byte reported-size bucket을, 연속 구간 합이 반복되는 최소 유효 주기로 16-request 균형 epoch을 추론한다. 문서 어디에도 16회 합산 공식은 적혀 있지 않다.
3. `layoutgen`을 역공학한다. 배포 ELF는 stdin을 읽지 않고 고정 self-test만 수행하므로 계산기로 사용할 수 없다. counter epoch과 style에 의해 선택되는 xorshift, avalanche, rotate-xorshift, rotate-avalanche 네 family를 독립 구현한다. 표본 64개가 모두 같은 `(layout, cover)`를 만든다는 사실로 canonical layout 2와 cover 0을 알아낸다.
4. 공개 flag 형식과 recovery 레코드라는 문제 맥락에서 `recovery=SHA{` probe를 구성한다.
5. counter를 추론한 epoch 경계에 맞춘 뒤 filler 0으로 한 epoch를 측정한다. 표본에서 관찰한 균형성 때문에 합계는 팀별 padding 순서와 무관하게 안정적이다.
6. 압축 접두사 일치로 총 길이가 가장 작아지는 후보를 다음 문자로 선택한다.
7. 12자리 payload를 복구하고 CRC16-CCITT를 계산한 뒤 완성 플래그 후보를 다시 길이 오라클로 확인한다.

레이아웃이 네 종류라서 같은 위치에 있는 미끼 레코드를 그대로 읽으면 오답이 된다. 공식 솔버는 ELF에서 복구한 생성 규칙과 calibration에서 추론한 canonical layout/cover를 매 요청 다시 맞춘다. 반면 서버 padding permutation은 배포 비밀과 팀 토큰, epoch에 묶이며 다음 epoch에서 다시 섞인다. 따라서 filler 0의 버킷을 본 뒤 4회 이진 탐색으로 경계를 찾는 기존 5요청 방식은 단조성을 잃고, 다른 팀이 알아낸 순서도 재사용할 수 없다.

## 실행

```bash
python3 build_assets.py
python3 run_tests.py
python3 build_assets.py --publish
python3 prepare_deployment.py --teams 90
docker compose up --build -d

# `for_admin/solution`에서 운영 HTTP 서비스 검증
SERVER_URL=http://web.roomescapectf2026.site:40569 \
TEAM_TOKEN="$(awk -F, 'NR==2 {print $2}' ~/.local/share/wargame-deployments/vault-boundary/team_tokens.csv)" \
  python3 solution/solver/solve.py
```

같은 서버에서 로컬로 검증할 때만 `SERVER_URL=http://127.0.0.1:40569`로 덮어쓴다. 솔버의 기본 주소는 CTFd에 표시되는 운영 고정 주소인 `http://web.roomescapectf2026.site:40569`이다.

일반 빌드와 테스트는 `for_admin/.build/for_user/`를 사용하며 실제 지급본은 수정하지 않는다. 검수한 관리자 빌드를 `for_user/`에 복사할 때만 `--publish`를 사용한다. Compose 출력의 `vault-boundary-example-token-` 뒤 48자리 값은 로컬 검증에 사용할 수 있는 `team-001` 토큰이다.

정적 인스턴스의 공식 풀이 측정량은 6,928회다. `/api/measure-batch`가 16개 epoch를 한 번에 묶어 실제 HTTP 요청은 약 28회로 줄지만, 예산은 내부 측정량 6,928회 그대로 차감된다. 다양한 유효 형식의 플래그 64개 회귀 검증에서도 모두 팀별 제한 16,000회 안이었다. 공식 solver는 서버 내부 모듈을 import하거나 `layoutgen`을 subprocess로 호출하지 않고 공개 schema evidence와 역공학으로 복구한 전이만 사용한다.

상태와 counter는 Redis Lua transaction으로 원자적으로 증가해 재접속으로 초기화되지 않는다. 재배포할 때는 새 `DEPLOYMENT_ID` namespace와 `PADDING_SECRET`이 적용되어 영속 Redis volume에 남은 이전 대회의 상태나 padding 순서가 새 팀에 영향을 주지 않는다. `run_tests.py`는 지급본 구성, answer-sheet marker 부재, calibration 추론, 배포 ELF 비계산기성, 관리자 harness 기반 4-family 동치, 비밀 padding의 permutation·팀 격리·합산 불변성, 기존 5요청 이진 탐색 실패, 일반적인 반분 group template과 후보 반복 증폭 실패, 무작위 플래그 풀이, 운영 비밀 fail-closed, 90팀 배포 파일 권한, 손상 WASM 거부를 검사한다.

추가 검수에서는 인증·32 KiB body 제한·UTF-8 512바이트 제한·팀 격리·동일 팀 counter 원자성·비루트 UID를 확인했다. 운영 서버에서 30개의 팀 토큰으로 전체 공식 풀이를 동시에 실행한 결과, 신규 상태 29팀은 모두 111.1초 이내에 플래그를 복구했다. 나머지 1팀은 이전 반복 검수로 요청 예산을 이미 소진하여 HTTP 429로 종료되었으며 동시성 오류는 없었다.
