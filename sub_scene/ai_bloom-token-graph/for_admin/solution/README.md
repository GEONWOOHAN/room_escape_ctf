# 공식 풀이 및 검증

## Flag

`SHA{bl00m_0r4cl3_tr4c3s_t0k3n_gr4phs}`

운영 배포에서는 `prepare_deployment.py`가 생성한 플래그로 교체된다.

## 핵심 구조

플레이어는 `normalizer.wasm`의 `lexicon` custom section에서 실제 토큰 ID를 복구하고, `vocab.txt`의 32개 payload 토큰을 대응시킨다. 출력 필터는 정규화 결과가 정확히 5토큰일 때만 검사하므로, 카운터와 공개 template 선택식을 역산해 prompt가 그대로 출력되는 seed를 골라야 한다.

각 5토큰 shingle은 FNV-1a 결과에 따라 세 profile 중 두 곳으로 라우팅된다. 두 profile에서 모두 `blocked`인 경우를 간선으로 보고 다음 토큰 후보를 확장한다. 부분 미끼와 완전 근접 미끼 때문에 한 경로만 탐욕적으로 따라가면 실패하며, 살아 있는 경로를 함께 유지해야 한다.

18토큰을 복구한 뒤 살아 있는 모든 경로의 마지막 `}` 간선까지 확인한다. 서버는 시작 prefix에서 도달 가능한 closure의 각 shingle에 대해, routed profile 중 하나의 `allowed` 또는 양쪽의 `blocked`가 실제 관측됐는지 팀별로 기록한다. 이 coverage가 완성되기 전 `/api/claim`은 payload의 정오를 구분하지 않고 `incomplete`만 반환한다. claim도 요청 예산을 소비하므로 마지막 토큰 대입이나 무료 후행 검증은 불가능하다. CRC는 더 이상 질의 가능한 그래프나 정답 엔트로피에 포함되지 않는다.

## 공식 솔버

서버 실행 후 다음과 같이 검증한다.

```bash
python3 prepare_deployment.py --teams 90
docker compose up -d --build

SERVER_URL=http://127.0.0.1:40542 \
TEAM_TOKEN="$(awk -F, 'NR==2 {print $2}' ~/.local/share/wargame-deployments/bloom-token-graph/team_tokens.csv)" \
  python3 solution/solver/hard.py
```

위 실행은 `for_admin/solution/`의 공식 검수 환경을 기준으로 한다. 솔버는 공개 `challenge.json`, `normalizer.wasm`, `vocab.txt`, 지급 generator에서 복구한 계산만 사용하며 서버의 `challenge.core`를 import하지 않는다. 로컬 전체 회귀검증은 `python3 run_tests.py`다. 검증용 지급 파일은 `for_admin/.build/for_user/`에 생성되며 실제 `for_user/`는 수정하지 않는다. 검수한 빌드를 배포할 때만 `python3 build_assets.py --publish`를 사용한다. 현재 128개 seed의 generate·claim 합산 요청량은 최소 1,619, 중앙값 1,790, p95 1,955, 최대 1,962회다. HTTP 서비스는 세션 발급 시에만 CTFd 토큰을 검증하며 공식 솔버는 HTTP/1.1 연결을 재사용한다.

## 운영상 중요한 점

- `X-Team-Token`의 SHA-256 값이 팀 ID다.
- 팀 ID와 인스턴스 번호, counter, 남은 예산, shingle/profile coverage는 SQLite에 저장된다.
- 세션을 새로 만들거나 연결을 끊어도 2,000회 제한은 초기화되지 않는다.
- 128개 인스턴스의 난도 편차는 의도된 것이며 모두 상한 아래로 검증한다.
- `prepare_deployment.py`가 작업 디렉터리 밖에 allowlist와 무작위 세션 비밀을 생성하고, 전 팀 공통 정적 플래그를 배포 환경에 기록한다.
- `--force` 재배포는 새 `DEPLOYMENT_ID` namespace를 사용하므로 기존 SQLite volume의 팀 배정과 카운터가 새 대회를 잠그지 않는다.
- 서버는 빈 allowlist를 거부하고 모든 POST에서 팀 헤더를 먼저 검사하며, 세션이 같은 팀에 속하는지도 확인한다.
- 회귀 테스트는 동일 팀 200개 동시 generate의 counter가 `0..199`로 중복 없이 소비되는지 검사한다. 배포 컨테이너에서도 90개 팀 토큰의 동시 session 요청이 서로 다른 90개 인스턴스로 정상 배정됨을 확인했다.
