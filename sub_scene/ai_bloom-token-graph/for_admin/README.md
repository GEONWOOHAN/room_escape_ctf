# Bloom Token Graph

## 의뢰서

**의뢰 이름:** AI 검열 필터에서 삭제된 18토큰 문장 복원

**의뢰인:** `BLACK.INK_404`

**의뢰 내용:**

말이 지워졌다고 흔적까지 사라지는 건 아니더군요. 검열 서버에서 뜯어낸 토크나이저와 어휘표를 보냅니다. 삭제된 문장은 18토큰이고, 다섯 토큰씩 겹쳐 보던 흔적이 검열 프로필 세 개에 흩어져 있습니다.

조회는 팀당 2,000번입니다. 다시 접속해도 안 돌아옵니다. 서버는 다섯 토큰짜리 창 하나만 받아들이고, 제출도 한 번으로 칩니다. 게다가 시작점에서 이어지는 분기를 전부 확인해야 정답인지 말해 줍니다.

그 문장이 대체 뭐였는지만 알려 주세요. 이유는 묻지 마시고요.

## 운영 정보

- 유형: 온라인 HTTP 오라클
- 플레이어 지급본: `for_user/`
- 서비스 코드: `for_admin/challenge/`
- 팀 인스턴스: 사전 생성된 128개 중 CTFd `team_id`별 하나를 영구 배정
- 제한: generate·claim 합산 팀별 누적 2,000회, 재접속·프로세스 재시작 후에도 SQLite에 유지
- 제출 gate: 시작 prefix에서 도달 가능한 모든 shingle을 한 routed `allowed` 또는 양쪽 routed `blocked`로 판정해야 함
- 플래그 형식: `SHA{...}`
- CTFd 정적 플래그: `SHA{bl00m_0r4cl3_tr4c3s_t0k3n_gr4phs}`

운영 배포는 `/api/session`에서 CTFd 개인 Access Token을 한 번 검증하고 `team_id`로 팀 인스턴스·2,000회 예산을 공유한다. 이후 generate·claim 요청은 서버가 서명한 세션을 bearer credential로 사용하므로 매 요청마다 CTFd를 호출하지 않는다. 같은 팀원의 다른 토큰은 같은 팀 상태를 사용한다. `prepare_deployment.py`가 만드는 자체 토큰 목록은 기존 로컬 테스트용이며 운영 인증에는 사용하지 않는다. 운영 비밀은 작업 디렉터리 밖에 생성한다.

Compose는 비루트 실행, 읽기 전용 루트 파일시스템, capability 제거, PID·CPU·메모리 제한과 로그 순환을 적용한다. 팀 상태 DB만 `bloom-token-state` volume에 기록된다.
재빌드에는 Python 3.12+, Node.js와 wasm32 target을 지원하는 `clang`이 필요하다. 지급본에는 검수된 `normalizer.wasm`이 이미 포함되어 있다.

```bash
python3 prepare_deployment.py --teams 90
python3 build_assets.py             # for_admin/.build/for_user 생성
python3 run_tests.py
python3 build_assets.py --publish   # 검수 후에만 ../for_user 교체
docker compose up -d --build
```

운영 Compose는 컨테이너 이름에 토큰을 표시하지 않는다. `build_assets.py`와 `run_tests.py`의 일반 실행은 관리자 작업 공간만 사용한다. 실제 `for_user/`를 쓰는 명령은 명시적인 `build_assets.py --publish`뿐이며, 완성된 `for_admin/.build/for_user/`를 복사해 지급본을 교체한다. 공식 풀이기는 지급본을 읽기만 한다.

기본 비밀 저장 위치는 `~/.local/share/wargame-deployments/bloom-token-graph/`이며 `deployment.env`와 `team_tokens.csv`를 플레이어에게 배포하면 안 된다. 팀별 shingle/profile 관측 이력도 같은 SQLite namespace에 저장된다. 현재 128개 인스턴스의 공식 풀이 generate·claim 합산 요청 수는 최소 1,619, 중앙값 1,790, p95 1,955, 최대 1,962회다. 풀이와 검증 근거는 `solution/README.md` 및 `solution/solver/`에 있다.
