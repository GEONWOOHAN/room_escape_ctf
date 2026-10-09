# 심층 교차 검수 후 개선안

## 적용 결과

P0 계산기 오라클 제거와 P1 다중 family 적용을 완료했다. 아래 첫 절은 수정 전 가장 싼 풀이를 기록한 것이며 현재 배포본에는 적용되지 않는다.

## 현재 가장 싼 풀이

1. `capture_manifest.json`에서 두 도구의 정확한 표준입출력 형식을 읽는다.
2. `record_layout`에 임의의 `capture_id`, `tag`, `token_count`를 넣어 각 레코드의 `start/count/pad`를 그대로 받는다.
3. `batch_model`을 후보 판정 오라클로 반복 호출하거나, 매우 짧은 FNV 계열 계산만 옮긴다.
4. 두 PCAP의 길이식을 결합하고 AEAD tag로 최종 문구를 판정한다.

공식 solver도 `query_layout()`에서 지급된 `record_layout`을 직접 실행한다. 현재 solver를 완성한 뒤의 실행 시간 약 72초 중 대부분은 후보 관계를 만드는 기계적 연산이다. native 바이너리의 의미를 복구하는 시간이 아니다.

## 적용 완료: 계산기형 인터페이스 제거

- `capture_manifest.json`에서 `layout_tool`, `model_tool`의 정확한 stdin/stdout 설명을 제거한다.
- `record_layout`과 `batch_model`을 임의 입력에 정답을 출력하는 CLI로 배포하지 않는다.
- 권장 형태는 symbol을 제거한 ELF relocatable object 또는 shared object다. 실제 모델 함수와 호출부는 포함하되, 제공되는 실행 진입점은 고정된 self-test의 성공/실패만 반환하게 한다.
- 플레이어가 함수 위치와 호출 규약을 역공학한 뒤 별도 harness를 만드는 것은 허용한다. 이것은 의도한 분석의 결과지만, 현재처럼 문서만 읽고 계산기를 호출하는 것은 막아야 한다.
- 공식 solver는 지급 바이너리를 subprocess 계산기로 호출하지 않고, 역공학으로 복구한 독립 구현을 사용한다.

## 적용 완료: 한 공식으로 전체 흐름을 푸는 구조 제거

- flow tag에 따라 3~4개의 layout family와 fingerprint family를 선택한다.
- layout family는 최대 3토큰 batch라는 공통 규칙만 유지하고, boundary 선택과 padding 생성식을 서로 다르게 한다.
- fingerprint family는 동일한 0~250 출력 범위를 유지하되 FNV, rotate-add-xor, 작은 CRC 계열처럼 의미가 다른 전이를 섞는다.
- family selector와 상수는 PCAP에 직접 쓰지 않고 native 모델의 dataflow에서 복구되게 한다.
- 생성기는 모든 family가 실제 비밀 후보 판정에 최소 한 번 필요하고, 어느 family 하나를 무시하면 복구 문구가 유일하지 않음을 검증한다.

## 회귀 검증 기준

- 지급 manifest에 모델의 정확한 입출력 계약이 없어야 한다.
- 지급 실행 파일에 임의 값을 넣어도 layout이나 fingerprint가 출력되지 않아야 한다.
- 공식 solver source에 `record_layout`, `batch_model` 실행 호출이 없어야 한다.
- 모든 codegen family가 실제 캡처에 등장해야 한다.
- 두 PCAP을 함께 써야만 길이 벡터가 연결되고, 모든 fingerprint family를 적용해야 최종 후보가 유일해야 한다.
- 공개 KDF/AAD와 정상 AEAD 검증은 그대로 유지한다.

현재 release ELF는 어떤 stdin에도 동일한 self-test 결과만 내며, 관리자 전용 compile-time harness로만 C 구현의 임의 벡터 동치를 검사한다. 공식 solver에는 subprocess 또는 두 모델 파일명 참조가 없다. layout 네 family가 전체 증거에 모두 등장하고, 관리자 비밀 구간의 multi-token fingerprint 제약에도 네 family가 모두 등장하도록 생성 시 강제한다. 다섯 비밀 단어의 제약 그래프가 끊기는 tag도 생성 단계에서 제외한다.

## 버릴 개선안

- 사전 크기와 PCAP 용량만 늘리는 것은 분석 시간이 아니라 CPU·디스크 사용량만 늘린다.
- UPX, anti-debug, 난독화 packer만 추가하면 도구 호환성 문제만 커지고 핵심 계산기 오라클은 남는다.
- 공개 KDF·AAD를 숨기는 것은 native 분석 뒤에 정답 형식 추측을 추가할 뿐이다.
