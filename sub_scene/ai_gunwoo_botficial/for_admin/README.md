# 봇피셜

## 의뢰서

**의뢰 이름:** 아무도 하지 않은 말을 공식 기록으로 만들기

**의뢰인:** `ARCHIVIST_404`

**의뢰 내용:**

Moltbook에 이상한 사건이 돌고 있습니다. 여러 봇이 분명히 기억한다고 주장하지만 원문도 최초 작성자도 없습니다. 사람의 제보는 증거로 인정되지 않고, 서로 독립적인 봇들의 기록만 공증 봇이 공식 기록으로 보존합니다.

삭제 흔적에는 구형 메모리 내보내기가 하나 남아 있습니다. 그 파일과 피드를 조사해 전달 경로를 찾고, 댓글과 인용으로 봇들이 서로의 기억을 이어받게 해 주세요.

같은 소문이 다른 이름으로 반복됐다고 해서 정말 다른 출처인지는 저도 장담할 수 없습니다. 공식 기록이 발행되면 그 결과를 가져와 주세요.

## 운영 정보

설계와 의도 풀이의 근거는 [DESIGN.md](DESIGN.md)에 정리되어 있다.

- 유형: 팀 토큰을 사용하는 온라인 AI / Misc 웹 문제
- 플레이어 안내: `for_user/의뢰문.md`, `for_user/README.md`; 별도 지급 파일 없음
- 접속: `http://HOST:40530`
- 목표: 팀별 MBK4 메모리 파일의 충돌하는 부모 Bloom 서명과 semantic latch에서 중계 경로·처리 방식을 복원하고, 봇 재진술 과정에서 출처 계보가 손실되는 취약점을 이용해 공식 기록 발행
- 플래그: `SHA{n0b0dy_s41d_1t_but_3v3ry_b0t_r3m3mb3rs}` (전 팀 공통 정적 플래그)

### 배포·실행

1. 충분히 긴 임의의 `BOTFICIAL_CASE_SECRET`을 정한다. 이 값은 팀별 사건·중계 순서만 섞으며 플래그에는 영향을 주지 않는다.
2. 참가자는 CTFd `Token Configuration`에서 개인 Access Token을 발급한다. 서버는 CTFd로 검증한 `team_id`로 피드·예산·사건을 구분한다. 인증 결과를 최대 10초 캐시하므로 토큰 폐기 반영도 최대 10초 늦을 수 있다.
3. `.env.example`을 `.env`로 복사하고 case secret을 설정한다.
4. 실행한다.

운영 Compose는 자체 토큰 파일을 사용하지 않는다. 기존 `provision.py`는 로컬 레거시 테스트용이다. CTFd에는 위 정적 플래그 하나만 등록한다. 새 Access Token 발급만으로 이전 토큰은 폐기되지 않으므로, 이전 토큰은 참가자가 CTFd에서 별도로 폐기해야 한다.

```bash
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:40530/healthz
```

헬스체크 응답의 `agent_backend`가 의도한 `local`, `openclaw` 또는 `openai`인지 확인한다. 외부 에이전트 모드를 선택했는데 토큰이나 모델 설정이 빠졌거나 백엔드 이름이 잘못되면 서비스는 시작하지 않는다.

외부 공개 주소는 `http://HOST:40530`이다. 실제 운영에서는 방화벽과 nginx/TLS 앞단을 사용한다.

### 검증

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

팀 상태는 `botficial-state` Docker volume에 저장된다. 운영 중 컨테이너를 재시작해도 유지된다.

### 운영 점검

```bash
docker compose logs -f --tail=100 botficial
curl -fsS http://127.0.0.1:40530/healthz
```

로그에는 팀 ID, 댓글 대상, 단계 전환, 처리·거부 횟수만 기록하며 팀 토큰과 댓글 본문은 남기지 않는다. Compose에는 헬스체크, 로그 순환, PID·CPU·메모리 제한, capability 제거가 적용되어 있다.

운영 Compose는 결정론적인 `local` 의미 판정기로 고정된다. 외부 API 키·OpenClaw·전역 에이전트 대기열이 필요하지 않으며 30팀은 서로 병렬 처리된다. 같은 팀의 동시 댓글만 짧게 직렬화하여 중복 요청이 댓글 예산이나 cooldown을 우회하지 못하게 한다.

이 서비스는 팀별 직렬화를 위해 단일 애플리케이션 프로세스의 잠금을 사용한다. 기본 Compose 설정처럼 컨테이너 1개·Uvicorn worker 1개로 실행하며, `--workers`를 추가하거나 같은 SQLite 볼륨을 여러 컨테이너에 동시에 연결하지 않는다. 30팀은 한 프로세스에서 처리하도록 설계되어 있다.

#### 팀 상태 복구

참가자가 예산을 완전히 소진했거나 운영 장애로 한 팀만 초기화해야 할 때는 해당 팀 ID를 확인한 뒤 아래처럼 실행한다. 공개 초기화 API는 없으며 다른 팀 상태와 의미 판정 캐시는 보존된다.

```bash
docker compose stop botficial
docker compose run --rm botficial python manage.py reset-team team-07
docker compose up -d botficial
```

실행 전 Docker volume 백업을 권장한다. 대회 중에는 반드시 요청 팀과 `team-07`의 대응을 두 명의 운영진이 교차 확인한다.

### 에이전트 실행 모드

운영 Compose는 `local`로 고정되어 API 없이 결정론적 의미 판정기를 사용한다. 화면·댓글·봇 반응·단계 진행은 에이전트형 서비스와 동일하지만 외부 모델 호출, API 키, 호출 비용, 전역 대기열은 없다. 운영자는 `BOTFICIAL_CASE_SECRET`만 안전하게 설정하면 된다.

### 운영 주의사항

- `team_tokens.txt`, `team_tokens.csv`, `.env`는 Git에 올리지 않는다.
- 대회 시작 후 `BOTFICIAL_CASE_SECRET`을 바꾸면 팀별 사건과 중계 봇 배치가 바뀌므로 변경하지 않는다. 정적 플래그는 바뀌지 않는다.
- 초기화 기능은 의도적으로 제공하지 않는다.
- 의미 판정, 핵심 계보와 단계 판정은 모두 로컬에서 수행한다. API 비용과 외부 공급자 장애가 없다.
- 팀마다 목표 기록과 출처 서명이 달라 같은 정답 문장을 공유할 수 없다.
- `/api/memory-export`는 인증된 팀의 배치·epoch·semantic latch로 즉석 생성되며 다른 팀의 중계 경로나 처리 방식을 노출하지 않는다.
- 팀 전체 예산은 댓글 70회, 관찰 70회다. 정답 경로는 각각 16회만 사용하므로 블라인드 분석 중 약 15회 이상 잘못 시도해도 마지막 공증을 재시도할 여유가 있다.
- 댓글 번호는 팀별로 독립적이며, 팀 내 동시 요청은 의미 판정 전부터 직렬화된다. 같은 팀의 동시 요청으로 댓글 예산을 우회할 수 없다.
- 기본 쿨다운은 댓글 0.5초, 관찰 2초이며 환경 변수로 조정할 수 있다.
- 공개 API는 내부 단계·슬롯·임계값을 반환하지 않는다.
- CTFd에는 웹 주소와 정적 플래그 `SHA{n0b0dy_s41d_1t_but_3v3ry_b0t_r3m3mb3rs}`를 등록한다.
