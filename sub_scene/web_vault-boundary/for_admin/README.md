# Vault Boundary

## 의뢰서

**의뢰 이름:** 회사 전자 금고의 실제 복구 레코드 탈취

**의뢰인:** `EX-DIRECTOR_11`

**의뢰 내용:**

내가 만든 회사에서 내가 쫓겨났습니다. 웃기는 일이죠. 복구 키도 바꿨더군요. 다행히 손님 계정의 공유 메모와 백업 내보내기는 아직 열려 있습니다.

내보내기 본문은 압축된 뒤 암호화되며 내용 대신 버킷 단위 크기만 보입니다. 레코드 배치는 요청 카운터와 seed, style에 따라 바뀌고 팀마다 다른 padding도 섞입니다. 첨부한 `schema.wasm`에는 예전 클라이언트가 남긴 최소 형식 정보와 64회의 관측 표본이, `layoutgen`에는 배치 선택 로직이 남아 있습니다. 둘 다 친절한 설명서는 아닙니다.

공유 메모를 끼워 넣어 관리자 백업의 진짜 `recovery` 레코드를 한 글자씩 확인하세요. 미끼가 몇 개 있습니다. 가짜 키를 들고 오면 보수도 가짜로 드리겠습니다.

## 운영 정보

- 유형: 온라인 FastAPI 압축 길이 오라클
- 플레이어 지급본: `for_user/`
- 상태 저장: Redis, deployment namespace 및 팀별 요청 카운터·메모 분리
- 기본 요청 제한: 팀별 16,000회
- 노이즈: 팀·배포·epoch별 균형 padding; 정확한 주기와 집계법은 관측 표본에서 추론
- 공식 풀이 기준: 내부 측정 6,928회, HTTP 배치 요청 28회 이하
- 다양한 유효 플래그 64개 회귀 검증 범위: 5,392~10,304회
- 지급 `layoutgen`: Linux x86-64 정적·stripped ELF, 고정 self-test만 실행, 4개 전이 family 내장
- 플래그 형식: `SHA{<12 hex>-<crc16>}`
- CTFd 정적 플래그: `SHA{a1b2c3d4e5f6-90d2}`
- 운영 고정 주소: `http://web.roomescapectf2026.site:40569`
- 동시 검수: 실제 운영 서버에서 팀별 독립 토큰으로 전체 공식 풀이를 병렬 실행

운영 배포는 `/api/session`에서 CTFd 개인 Access Token을 한 번 검증하고 `team_id`로 Redis 상태와 요청 제한을 공유한다. 이후 요청은 12시간 유효한 무작위 세션 토큰을 사용한다. 같은 팀원의 다른 토큰·재발급 토큰은 같은 팀 상태를 사용한다. `/api/measure`는 공유 메모 설정과 최대 16회 export를 하나의 원자적 요청으로 처리한다. `/api/measure-batch`는 이 묶음을 최대 16개까지 한 HTTP 요청으로 처리한다. 어느 API를 사용해도 예산은 실제 내부 측정 횟수만큼 동일하게 차감된다. 아래 `prepare_deployment.py`가 만드는 토큰 목록은 기존 로컬 테스트용이며 운영 인증에는 사용하지 않는다. 플래그·padding 비밀을 준비한다.

서비스는 암호문 본문을 반환하지 않고 길이만 공개하므로 AES-GCM의 `nonce 12바이트 + tag 16바이트` 길이 증가분을 직접 계산한다. 같은 note/layout의 압축 결과는 프로세스별 LRU 캐시에 저장한다. 이는 오라클 출력과 풀이 계약을 바꾸지 않으면서 30팀 동시 측정에서 반복 압축·난수 생성·암호화 비용을 제거한다.

```bash
python3 build_assets.py             # 관리자 빌드
python3 run_tests.py
python3 build_assets.py --publish   # 검수 후 지급본 교체
python3 prepare_deployment.py --teams 90
docker compose up --build -d
```

운영 Compose는 컨테이너 이름에 토큰을 표시하지 않는다. 일반 빌드와 테스트는 `for_admin/.build/for_user/`만 사용한다. 실제 `for_user/`를 쓰는 명령은 명시적인 `build_assets.py --publish`뿐이며, 완성된 관리자 빌드를 복사해 지급본을 교체한다. 공식 풀이기는 지급 파일을 읽기만 하고 서버 요청만 전송한다.

기본 비밀 저장 위치는 `~/.local/share/wargame-deployments/vault-boundary/`이다. 그 아래의 `deployment.env`와 `team_tokens.csv`를 플레이어에게 배포하면 안 된다. `deployment.env`에는 매 배포마다 새 `DEPLOYMENT_ID`가 들어가므로 Redis volume을 유지한 채 재배포해도 이전 counter와 섞이지 않는다.

`schema.wasm`에는 canonical layout, bucket/epoch 크기, 압축·직렬화 방식, probe prefix, padding 순열 설명, stable score 공식이 들어 있지 않다. 플레이어는 관측 표본의 크기 공약수와 반복 합계, 그리고 ELF의 counter-dependent dataflow를 분석해야 한다.

운영 컨테이너는 runtime `FLAG`와 `PADDING_SECRET`이 없으면 시작하지 않는다. CTFd 검증에 실패한 요청은 거부한다. 앱은 UID 10001 비루트 계정으로 실행되고 worker별 동시 요청 상한도 적용된다. 자세한 공격 과정과 운영 검증은 `solution/README.md`에 있다.

앱과 Redis에는 읽기 전용 루트 파일시스템, capability 제거, PID·CPU·메모리 제한과 로그 순환이 적용된다. Redis 영속 데이터만 `vault-state` volume에 기록된다.

이 문제 단독 운영은 4 vCPU·8 GiB·SSD를 최소 권장하고, `bloom-token-graph`와 같은 호스트에서 90팀 burst를 받을 때는 8 vCPU·16 GiB를 권장한다. POST 본문은 32 KiB로 제한된다.
