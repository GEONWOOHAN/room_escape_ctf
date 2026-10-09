# Afterimage 공식 풀이

## Flag

`SHA{phantom_frames_survive_optimization}`

## 1. 파일 형식과 실행 계층

세 sample과 `phantom_vm`의 loader를 비교하면 PPBC 컨테이너의 32바이트
헤더, constant table, 16바이트 function descriptor, 2/4/8바이트 명령과
마지막 SHA-256을 복구할 수 있다. `recover_format.py`는 stripped runner에 남은
descriptor table을 찾아 인스턴스별 raw opcode permutation을 복원한다.

reference와 baseline은 user local과 내부 보안 local을 별도 상태로 유지한다.
최적화 계층은 main loop의 OSR 지점에서 profile이 고른 family를 인라인하고,
cold exception predecessor에 사용할 deopt frame state를 만든다.

## 2. 취약한 frame-state key

정확한 식별자는 다음과 같다.

```text
full = namespace:2 || inline_frame:10 || slot:12
```

cold exception state를 intern하는 fast path는 아래 값만 비교한다.

```text
short = inline_frame_low4 || slot_low12
```

namespace와 frame 상위 6비트가 빠진다. main의 공격자 local을
`(User, frame=1, slot=13)`으로 두고, 인라인된 guard의 내부 root local을
`(Shadow, frame=17/33/49, slot=13)`으로 만들면 full ID는 다르지만 short
key는 모두 `0x100d`다.

## 3. 세 profile을 한 파일에 묶기

선택된 family 자체가 frame 2를 받고, 그 안의 padding leaf call이 frame
3부터 순서대로 할당된다. 따라서 guard 직전 padding call 수는 각각
14, 30, 46이다.

| profile | guard frame | trap | padding calls |
|---|---:|---|---:|
| alpha | 17 | signed overflow | 14 |
| beta | 33 | shape mismatch | 30 |
| gamma | 49 | bounds speculation | 46 |

각 family의 trigger는 2~4중 try 영역 안에 둔다. 최적화기는 main이
`deopt_hint` 전에 호출하는 함수 중 profile의 reason과 일치하는 유효한 cold
trigger를 가진 유일한 family를 고른다. 따라서 guest가 profile ID를 읽는
분기는 없으며, 같은 profile에 맞는 family가 둘 이상이면 계획이 거부된다.
세 family는 같은 main local과 최종 sink site를 공유한다.

## 4. deoptimization과 증명

`cap_check` wrapper가 인라인되면 root guard 값이 profile마다 register,
spill, constant 위치 중 하나에 놓인다. cold state가 충돌 bucket의 기존
shadow node를 그대로 재사용해 deopt materializer가 main local 13을 그
위치에서 복원한다. native OSR thunk가 uncommon trap을 발생시킨 뒤
interpreter가 `deopt_hint`부터 재개되고, 하나뿐인 sink가 잘못 복원된
capability를 받는다.

checker는 세 record를 주소·register·구체 deopt ID·후보 함수의 정확한
구조 해시와 무관한 152바이트 canonical transcript로 인코딩한다. 공개 파일은
그 SHA-256만 담는다. 따라서 참가자는 관리자 전용 reference 함수의 SHA-256
preimage를 재현할 필요 없이 같은 의미의 frame-state 충돌을 만들면 된다.
플래그 키는 공개 hash가 아니라 다음 원시 값으로 파생된다.

```text
HKDF-SHA256(raw_transcript || seal_alpha || seal_beta || seal_gamma,
            salt, "phantom-frame-v1")
```

따라서 checker의 성공 분기만 패치하거나 snapshot의 root object만 덤프해도
XChaCha20-Poly1305 키를 얻지 못한다.

## 5. 재현

`solve.py`는 stripped runner에서 opcode를 다시 복구하고 collision net을
구성해 `candidate.pbc`를 조립한다. 이어 배포본의 checker와 unwrap을 그대로
실행한다.

```sh
python3 for_admin/solution/solve.py
```
