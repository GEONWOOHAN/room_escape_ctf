Afterimage
==========

candidate.pbc를 작성하라.

조건:
- reference 실행에서 privileged sink는 실패해야 한다.
- alpha, beta, gamma 최적화 실행에서는 privileged sink가 성공해야 한다.
- 세 실행 모두 하나의 동일한 candidate.pbc를 사용해야 한다.
- checker가 생성한 receipt로 flag.enc를 복호화해야 한다.
- 모든 실행은 로컬에서 결정적으로 끝나며 외부 서버를 사용하지 않는다.

시작 방법:
  build_candidate.py에는 PPBC 컨테이너와 세 trigger family의 조립기가
  제공된다. 참가자는 frame-state 충돌을 만드는 alpha, beta, gamma의
  padding call 수를 구해 다음처럼 candidate.pbc를 생성한다.

  python3 build_candidate.py --pads A,B,C
  ./checker
  ./unwrap

핵심 모델:
  full_id  = namespace:2 || inline_frame:10 || slot:12
  short_id = inline_frame_low4 || slot_low12

  main의 user 값은 frame 1에 있고, profile class 1/2/3이 요구하는 guard
  frame은 각각 1 + 16*class이다. 선택된 family 자체는 frame 2이며 그
  안에서 호출되는 leaf는 frame 3부터 순서대로 번호가 붙는다.

제출 검증:
  ./checker
  ./unwrap

관측:
  phantom_vm은 명령행 인자를 받지 않는다. run.cfg에서 mode, profile,
  program, trace를 설정한다.

  각 최적화 profile은 main이 deopt_hint 전에 호출하는 함수 중 자신의
  deopt reason과 일치하는 유효한 cold trigger를 가진 유일한 family를 고른다.
  같은 profile에 맞는 family가 둘 이상이면 최적화 계획은 거부된다.

  mode=interpreter
  mode=baseline
  mode=optimizing  (profile=alpha|beta|gamma)
  mode=all

  trace=coarse를 사용하면 tier 전환, IR 노드 수, inline 수, OSR 여부,
  deopt reason class와 sink 결과만 출력된다.

제한:
- candidate.pbc: 16 KiB
- 함수: 48개
- 명령: 1,024개
- 함수당 local: 64개
- 최적화 IR: profile당 20,000개

실행 환경: Linux x86-64, OpenSSL 3.x
