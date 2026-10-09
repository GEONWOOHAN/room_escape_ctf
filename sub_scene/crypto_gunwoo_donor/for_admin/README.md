# DONOR

## 의뢰서

**의뢰 이름:** 폐기 보안 프로세서의 보관소 권한 복구

**의뢰인:** `LAST_DONOR`

**의뢰 내용:**

폐기 예정 장비에서 보안 프로세서 하나를 회수했습니다. 관리자 자격 증명은 이미 없어졌고, 현재 세션에는 손님 권한만 남아 있습니다. 보관소의 자료는 암호화된 메모리 안에 있습니다.

유지보수 인터페이스로 메모리 외피를 확인하고 암호문 블록을 다른 위치에 기록할 수 있습니다. 같은 펌웨어 계열의 분석용 프로세서 `donor-probe`도 첨부합니다. 다만 장치의 NVM 수명이 다해 가서 한 연결에 허용되는 유효 쓰기는 세 번뿐입니다.

키를 추출할 필요는 없습니다. 세 번의 기록으로 현재 세션에 보관소 읽기 권한을 부여하고 최종 검증을 통과해 주세요. 작업 대상 주소는 문제 페이지에 있습니다.

## 운영 정보

- 유형: 온라인 Crypto / Pwn TCP 서비스
- 플레이어 지급본: `for_user/donor-probe`; 안내문은 `for_user/의뢰문.md`, `for_user/README.md`
- 접속: `nc HOST 40577`
- 플래그: `SHA{transpl4nted_c1ph3rt3xt}`
- 제한: 연결당 유효 쓰기 3회; 연결마다 독립된 세션

Ubuntu 24.04에서 `build_player.sh`로 플레이어 바이너리를 빌드한 뒤 `python3 -m unittest -v test_service.py`로 검증한다. 운영 플래그는 `DONOR_FLAG` 환경 변수로 주입하고 `docker compose up --build -d`로 실행한다. 자세한 빌드·풀이 검증은 [solution/README.md](solution/README.md)에 있다.
