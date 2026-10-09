# Token Length Forensics

## 의뢰서

**의뢰 이름:** 감청 패킷 두 묶음에서 관리자 복구 문구 추출

**의뢰인:** `silent_5!`

**의뢰 내용:**

잡았습니다. 관리자 복구 문구가 오간 순간이요. 그런데 장비 두 대가 패킷을 서로 다르게 잘라 놨습니다. 재전송에 순서 뒤바뀜, 토큰 묶음, 패딩까지 엉망입니다.

관리자 프로그램이 보내는 문장은 `the recovery phrase is <사전 단어 5개> . verify now` 형식입니다. 꺾쇠 부분의 다섯 단어가 실제 복구 문구이며 모두 지급한 `dictionary.txt`에서 선택됩니다.

두 캡처에 든 24개 세션은 같은 겁니다. 경계만 다릅니다. 비교용 정상 세션, 사전, 현장에서 주운 실행 파일 두 개도 같이 보냅니다.

둘을 맞춰서 다섯 단어를 찾아 주세요. 한쪽만 보고 찍지는 마세요. 이번에는 틀릴 시간이 없습니다.

## 운영 정보

- 유형: 오프라인 패킷 포렌식·네이티브 역공학
- 플레이어 지급본: `for_user/`
- 핵심 파일: `capture_a.pcap`, `capture_b.pcap`, `record_layout`, `batch_model`, `dictionary.txt`, `flag.enc`
- 파일 역할: 두 PCAP은 서로 다른 batching 관측, `known_sessions.txt`는 고정 overhead 보정, 두 ELF는 layout·fingerprint 역공학 대상, `dictionary.txt`는 다섯 비밀 단어의 후보, `flag.enc`는 최종 AEAD 검증 대상
- 논리 세션: 24개
- 사전 단순 조합: 최소 34,359,738,368개 (`128^5`)
- 사전 후보는 정답을 포함해 동일한 불투명 문자열 생성 분포를 사용하며, 정답 위치는 길이별로 독립 선택
- 단일 캡처 잔여 후보: 관리자 정답 길이를 미리 안다고 가정해도 각 캡처 최소 500,000개
- 기준 풀이의 양쪽 캡처 결합 후보: 생성 시 100,000개 미만이 되도록 구조 검증 후 AEAD tag로 최종 판정
- 모델 다양화: tag별 layout 4종, 관리자 비밀 구간에 fingerprint 4종 모두 사용
- 지급 실행 파일: Linux x86-64 정적·stripped ELF, 고정 self-test만 실행
- 플래그 형식: `SHA{...}`

```bash
python3 generator/generate_challenge.py             # 관리자 빌드
python3 run_tests.py
python3 generator/generate_challenge.py --publish   # 검수 후 지급본 교체
```

일반 생성과 테스트는 `for_admin/.build/for_user/`만 초기화하고 사용한다. 실제 `for_user/`는 명시적인 `--publish` 실행에서만 완성된 관리자 빌드의 복사본으로 교체된다. 공식 풀이기의 기본 입력은 배포된 지급본이지만 파일은 읽기만 하며, 회귀 테스트에서는 관리자 빌드를 별도로 지정한다.

운영 플래그는 `TLF_FLAG_FILE=/path/to/flag`로 주입할 수 있다. 정답 평문과 복구 문구는 지급본에 포함되지 않으며, 플레이어가 복구 문구를 얻은 뒤 봉인 방식을 추측하지 않도록 KDF·AAD는 `capture_manifest.json`에 공개한다. 두 ELF는 내부 모델을 역공학할 단서만 제공하며 stdin을 계산기처럼 처리하지 않는다. 두 캡처의 flow 순서·클라이언트 주소·패킷 ID는 서로 독립적으로 섞이므로 tag 외의 위치 정보로 관리자 세션을 찍을 수 없다. 공식 분석 절차는 `solution/README.md`, 자동 검증 코드는 `solution/solver/solve.py`에 있다.
