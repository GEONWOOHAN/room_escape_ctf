# 공식 풀이 및 검증

## Flag

`SHA{token_lengths_require_cross_capture_alignment}`

## 풀이 흐름

1. 두 PCAP에서 Ethernet/IPv4/TCP를 파싱하고 4-tuple별 stream을 sequence number 기준으로 재조립한다. 재전송과 out-of-order segment를 중복 제거해야 한다.
2. `known_sessions.txt`의 평문 세션과 레코드 길이를 비교해 고정 overhead 29바이트를 구한다.
3. stripped ELF `record_layout`을 역공학해 tag별 family selector와 네 종류의 boundary/padding 전이를 복구한다. 배포 바이너리는 고정된 내장 self-test만 실행하며 임의 입력의 layout을 출력하지 않는다.
4. 캡처 A와 B의 서로 다른 경계를 합치면 모든 개별 토큰 길이가 복원된다. 어느 한 캡처만으로는 관리자 벡터가 결정되지 않는다.
5. 공개된 `the recovery phrase is <사전 단어 5개> . verify now` 형식과 일치하는 12-token flow 후보를 고른다.
6. `batch_model`에서 capture/tag/record별 selector와 FNV, rotate-add-xor, CRC, multiply-rotate 계열 네 전이를 복구해 TCP ACK window 관측치와 대조한다. 이 바이너리 역시 임의 후보를 판정해 주지 않는다. 한 토큰짜리 레코드의 지문은 의도적으로 내용과 무관하므로 관리자 정답 길이를 알아도 캡처 하나만으로는 각 캡처에서 최소 500,000개 후보가 남는다. 관리자 비밀 토큰에 닿는 multi-token 레코드가 네 family를 모두 사용하며, 두 캡처의 제약 그래프는 다섯 비밀 단어를 하나의 연결 성분으로 묶는다. 두 캡처의 관계를 조인하면 전체 phrase-shaped flow에서 100,000개 미만의 문장 후보가 남는다. 사전의 모든 길이별 후보는 같은 불투명 문자열 분포에서 생성되고 정답의 길이별 순위도 독립적이므로, 자연어 여부나 연속 행 번호로 후보를 거를 수 없다.
7. 각 후보로 AES-GCM 키를 파생해 `flag.enc`의 tag를 확인한다.

## 실행

```bash
python3 for_admin/solution/solver/solve.py
```

위 명령은 `for_admin/solution/`의 공식 검수 환경을 기준으로 한다. 공식 solver는 배포 ELF를 실행하거나 관리자 코드를 import하지 않는다. 두 바이너리에서 복구한 family selector와 전이를 Python으로 작성해 공개 PCAP에 적용한다.

테스트는 두 캡처의 24개 논리 flow 일치, 캡처별 endpoint 순서 독립성, 관리자용 harness를 통한 네이티브/생성기/독립 solver 128세트 동치, 배포 ELF의 비계산기성, 네 family 실사용, singleton 지문 비누출, 양쪽 단일 캡처의 길이 복원 실패, 캡처별 50만 후보 하한, 제약 그래프 연결성, 사전 표식·정답 순위 패턴 부재, 평문 누출, 공개 봉인 규격, 공식 복호화를 포함한다.
