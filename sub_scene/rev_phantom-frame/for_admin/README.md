# Phantom Frame

## 의뢰서

**의뢰 이름:** 폐기된 최적화 VM의 권한 잔상 재현

**의뢰인:** `FRAME_GHOST`

**의뢰 내용:**

폐기 직전 VM에서 유령을 봤습니다. 비유가 아닙니다. 평범하게 돌리면 금고 문 앞에서 막히는 코드가, 최적화만 시작하면 세 프로필 모두 안쪽까지 들어갑니다.

실행기, 프로필, 메모리 스냅샷을 보냅니다. `candidate.pbc` 하나로 재현해 주세요. reference에서는 실패하고 alpha, beta, gamma에서는 전부 성공해야 합니다. 검사기 출력만 꾸미면 바로 압니다. 제가 필요한 건 검증기가 찍어 준 receipt와 그 안의 기록입니다.

## 운영 정보

`for_user/`가 그대로 배포할 디렉터리다. `for_admin/`에는 VM 소스,
인스턴스 생성기, 테스트, 공식 풀이와 평문 플래그가 있으므로 배포하지 않는다.

빌드 및 패키징:

```sh
cd for_admin
make package
make test
```

`make package`는 공식 후보를 조립해 프로파일과 commitment/암호문을 생성한 뒤,
플레이어용 `candidate.pbc`를 안전한 starter 파일로 되돌린다.
새 인스턴스는 `instance.seed`를 바꾼 다음 `make package`로 만든다. seed에 따라
snapshot 배치, capability lineage/seal state, shape history, PGO budget/selector,
OSR logical class, commitment와 플래그 키가 함께 바뀐다.

공식 검증:

```sh
cd solution
python3 solve.py
```

이 명령은 후보를 다시 합성하고 플레이어와 같은 `checker`, `unwrap` 경로를
사용한다.
