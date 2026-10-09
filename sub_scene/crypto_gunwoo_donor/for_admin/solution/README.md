# DONOR 운영 정보

- 분야: Crypto / Pwn
- 포트: 40577/TCP
- 플래그: `SHA{transpl4nted_c1ph3rt3xt}`
- 예상 난이도: 중
- 예상 풀이 시간: 20~30분

## 빌드·실행

Ubuntu 24.04 기준 빌드 의존성은 `build-essential`, `libssl-dev`, `zlib1g-dev`이며 테스트에는 `requirements.txt`의 Python 패키지가 필요합니다.

```bash
chmod +x build_player.sh
./build_player.sh
python3 -m unittest -v test_service.py
DONOR_FLAG='SHA{local_test_flag}' docker compose up --build -d
python3 solution/exploit.py
```

원격 검증은 `python3 solution/exploit.py HOST 40577`로 실행합니다.

운영 환경에서는 파일을 수정하지 않고 `DONOR_FLAG` 환경 변수로 실제 플래그를 주입합니다. 각 TCP 연결은 독립된 키·routing nonce·메모리를 사용하므로 참가자 간 상태가 공유되지 않습니다.
컨테이너 상태는 compose healthcheck로 확인할 수 있으며, 연결당 유효 쓰기는 3회로 제한됩니다.

플래그를 지정하지 않으면 서비스는 제출 가능한 형식이 아닌 개발용 문자열을 사용합니다.

플레이어 ELF는 Ubuntu 24.04의 glibc와 `libcrypto.so.3`을 기준으로 빌드합니다. 참가자에게는 빌드에 사용한 `for_user/donor-probe`를 그대로 제공합니다.
