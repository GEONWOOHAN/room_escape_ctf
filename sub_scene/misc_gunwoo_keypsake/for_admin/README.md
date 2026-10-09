# KEYPSAKE

## 의뢰서

**의뢰 이름:** 암호화된 기록 보관소의 삭제 문서 복구

**의뢰인:** `N0_KEY_LEFT`

**의뢰 내용:**

자료 보관 서버가 랜섬웨어에 감염됐습니다. 대응팀이 도착했을 때 백업 볼륨은 이미 암호화됐고, 복호화 키는 메모리에서 지워진 뒤였습니다. 당시 실행 중이던 기록 보관 서비스의 메모리 덤프와 암호화된 백업 볼륨을 첨부합니다.

볼륨 안에서 삭제된 정산 확인서를 찾아야 합니다. 키 자체는 남아 있지 않지만, 서비스를 실행하며 생긴 텔레메트리와 계산 흔적 일부가 덤프에 남아 있습니다. 손상된 기록도 섞여 있으니 발견한 값을 곧바로 믿지는 마세요.

남은 흔적에서 복호화에 필요한 값을 재구성하고 볼륨을 복구한 뒤, 삭제된 확인서에 담긴 인증 코드를 찾아 주세요. 첨부 자료는 `KEYPSAKE.zip`에 있습니다.

## 운영 정보

- 유형: 정적 파일 Misc (Forensics / Reverse Engineering / Cryptography); 접속 서버 없음
- 플레이어 지급본: `for_user/KEYPSAKE.zip`; 안내문은 `for_user/의뢰문.md`, `for_user/README.md`
- 플래그: `SHA{wh3n_k3ys_v4n1sh_m3m0ry_r3m3mb3rs}`
- ZIP SHA-256: `1e52a32d4d2f64c2fe9b1df511118a1ca61f65c8162bb03245a9a65ee6f32d45`

참가자에게는 `KEYPSAKE.zip`만 배포한다. CTFd 업로드 제한은 최소 128 MiB, 권장 256 MiB로 설정하고, 업로드 전후 ZIP 해시를 대조한다. 공식 풀이 및 배포물 검증 명령은 [solution/README.md](solution/README.md)에 있다.
