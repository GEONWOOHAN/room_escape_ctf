# 주말에 뭐 하세요? 바쁘세요? 해결 가능하신가요?

서울시립대학교에서 진행한 방탈출 CTF의 문제 및 공식 풀이 자료입니다.

이 저장소에는 직접 제작한 메인 의뢰 2개와 추가 의뢰 10개를 정리했습니다. 각 문제는 참가자 제공 자료인 `for_user`와 출제·배포·검수 자료인 `for_admin`으로 구분되어 있습니다. `for_admin`에는 공식 풀이와 플래그를 포함한 관리자 자료가 있으므로 대회 문제로 재사용할 때는 공개 범위를 다시 확인해야 합니다.

## 문제 목록

### 메인 의뢰

- `4-2` 삭제된 CCTV
- `4-4` 탐정의 흔적

### 추가 의뢰

- Bloom Token Graph
- BOTFICIAL
- DONOR
- Token Length Forensics
- KEYPSAKE
- Selective State Rewind
- No Stack, Still Turing
- Ghost Callback
- Phantom Frame
- Vault Boundary

## 디렉터리 구조

```text
main_scene/
└─ 4-CCTV관리실/
   ├─ 4-2/
   └─ 4-4/

sub_scene/
├─ ai_bloom-token-graph/
├─ ai_gunwoo_botficial/
├─ crypto_gunwoo_donor/
├─ forensic_token-length-forensics/
├─ misc_gunwoo_keypsake/
├─ misc_selective-rewind/
├─ pwn_no-stack-still-turing/
├─ rev_ghost-callback/
├─ rev_phantom-frame/
└─ web_vault-boundary/
```

문제별 실행 방법, 의뢰문과 공식 풀이 과정은 각 디렉터리의 `README.md` 및 `for_admin/solution`을 참고하십시오.

## 대용량 파일

일부 참가자 제공 파일은 Git LFS로 관리합니다. 저장소를 받은 뒤 다음 명령으로 내려받을 수 있습니다.

```bash
git lfs install
git lfs pull
```

## 주의사항

- 본 저장소의 코드는 교육 및 CTF 학습을 위한 자료입니다.
- 문제 서버를 외부에 공개할 때는 기본 비밀값과 플래그를 반드시 교체하십시오.
- 실제 서비스나 권한이 없는 시스템을 대상으로 풀이 코드를 사용하지 마십시오.

