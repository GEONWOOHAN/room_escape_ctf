# 4-4 Archive Sweeper — 운영 배포

## 팀 식별

운영 배포의 `docker-compose.yml`은 CTFd 개인 Access Token을 사용합니다. 참가자는 CTFd의 `Token Configuration`에서 토큰을 발급한 뒤 `nc <문제 서버> 40526` 접속 시 `Team token:` 프롬프트에 입력합니다. 외부 접속 포트의 기본값은 `40526`이며 `HOST_PORT`로 변경할 수 있습니다. 토큰은 CTFd `/api/v1/users/me`로 **매 접속마다** 검증되며, 응답의 `team_id`가 작업 공간을 결정합니다. 같은 팀원은 서로 다른 개인 토큰을 사용해도 같은 공간을 공유합니다. 다른 팀의 상태와 파일은 분리됩니다.

팀 진행 상태는 `archive-sweeper-state` Docker volume에 원자적으로 저장되며 컨테이너 재시작 후 복원됩니다. 기본 동시 연결 상한은 128개, CTFd 검증기 동시 실행 상한은 8개, 인증 입력 제한 시간은 15초, 인증 후 유휴 제한 시간은 300초입니다. 각각 `MAX_ACTIVE_CONNECTIONS`, `MAX_CONCURRENT_AUTH`, `AUTH_TIMEOUT_SECONDS`, `IDLE_TIMEOUT_SECONDS`로 조정할 수 있습니다. 검증기 상한은 토큰을 캐시하지 않고도 30명 동시 입장 시의 메모리 급증을 제한합니다.

발급된 토큰은 발급 화면에서 한 번만 볼 수 있습니다. 새 토큰을 발급해도 기존 토큰은 자동 폐기되지 않으므로, 이전 토큰을 무효화하려면 CTFd에서 별도로 폐기해야 합니다. CTFd 검증이 실패하거나 CTFd가 응답하지 않으면 접속을 거부합니다. Access Token은 계정 API 권한도 가지므로 채팅이나 저장소에 공유하지 마세요.

## 실행

`CTFD_BASE_URL`의 기본값은 `https://contest.roomescapectf2026.site`입니다. 실제 CTFd 주소가 바뀌면 환경변수로 지정합니다.

```sh
./build.sh
CTFD_BASE_URL=https://contest.roomescapectf2026.site docker compose up --build -d
docker compose ps
```

운영 Compose에는 `team_tokens.txt`를 마운트하지 않습니다. `for_user/`의 Compose와 토큰 파일은 참가자용 로컬 연습의 기존 모드로 남겨뒀습니다. 플래그는 이미지의 `/home/ctf/flag`에서 읽습니다. 운영진은 로컬 테스트 플래그를 실제 대회 플래그로 교체해야 합니다.

## 검증

`test_ctfd_auth.py`는 로컬 가짜 CTFd로 같은 팀의 두 토큰, 다른 팀의 상태 격리, 컨테이너 재시작 복원, 폐기·미발급 토큰 거부 및 30팀 동시 접속을 검사합니다. 실제 CTFd 계정이나 토큰은 사용하지 않습니다.

```sh
python3 test_ctfd_auth.py
```
