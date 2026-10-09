# KEYPSAKE — Official Write-up

## 문제의 중심

랜섬웨어의 ephemeral scalar 자체는 소거되었다. 그러나 scalar multiplication을 준비하던 telemetry provider가 사용한 signed-window 표현은 손상된 상태로 MiniDump에 남았다. 문제의 핵심은 AES 키를 검색하는 것이 아니라 그 표현을 복구해 `Q = eG`를 만족하는 `e`를 재구성하는 것이다.

## 1. 세 아티팩트 연결

`records_backup.vhd.kpsk`의 끝에는 길이로 끝나는 TLV footer가 있다. CRC32와 BLAKE2s digest를 검증하면 context, file token, volume id, ephemeral public point, operator public point, wrapped key와 encrypted manifest를 얻는다. 이 값들은 MiniDump에서 올바른 context record를 식별하는 입력이다.

검증점: footer CRC32와 BLAKE2s가 모두 일치한다.

## 2. provider image 재구성

덤프의 context record는 provider 주소를 cookie로 보관하지만 원래 private image는 0으로 지워져 있다. 배포된 `telemetry_provider.dll`에서 provider interface와 변환 규칙을 분석할 수 있다. 덤프에 흩어진 PE section fragment 30개는 DLL과 같은 image인지 교차 검증하는 경로로 남아 있다.

덤프에는 `Records Archive Crypto Telemetry` registration도 남아 있다. 이는 transition sample과 sample confidence가 연산 성능 및 crash recovery를 위해 서로 다른 channel에 기록됐다는 제품상의 이유를 제공한다. registration은 ECDH와 channel 구조까지만 알려 주며, width 5와 sample count 257은 provider interface에서, P-256은 footer의 65-byte uncompressed point와 256-bit scalar 처리에서 각각 판별해야 한다. 단일 문자열이 분석 결과를 그대로 누설하지 않는다.

재구성한 image에서 record/page 구조, 포인터 cookie, SipHash key derivation, payload transform과 digit encoding을 리버싱한다.

검증점: registration CRC32, 모든 fragment checksum과 재구성한 PE section 배치가 일치한다.

## 3. 두 residue chain

context record에는 digit chain과 reliability chain의 head cookie가 따로 존재한다. 각 page는 Gray-coded ordinal, chain kind, 세 payload transform 중 하나, used length와 keyed SipHash tag를 가진다.

cookie를 풀고 page를 순서대로 복구하면 다음 길이가 나온다.

```text
digit chain       290 bytes
reliability chain 128 bytes
```

digit chain은 257개 masked digit과 33바이트 suspicious bitmap으로 구성된다. reliability chain 앞 33바이트는 실제 correction bitmap이다. 나머지는 PRNG filler다.

검증점: 모든 SipHash tag, ordinal, chain tail과 `290 + 128` 길이가 일치한다.

## 4. signed digits 복구

provider의 shuffle PRNG와 permutation을 역으로 적용하고 각 digit mask를 제거한다. 표현은 257자리이며 유효 digit은 `0` 또는 `-15..15`의 홀수다. suspicious bitmap에는 32개 위치가 있지만 correction bitmap이 가리키는 실제 손상은 24개다.

이는 임의의 signed representation이 아니라 표준 width-5 wNAF다. 모든 비영점 digit은 홀수이고 절댓값이 16보다 작으며, 인접한 비영점 사이에는 최소 5자리의 간격이 있다. 전체 digit을 합산하면 원래 scalar가 정확히 재구성된다. 생성기의 `qualify`도 이 네 조건을 독립적으로 강제한다.

손상 digit은 저장된 5-bit code에서 정확히 한 bit가 사라진 후보만 허용한다. 따라서 각 위치의 후보 집합은 provider의 encoding 규칙으로 결정되며 임의 상수 추측이 필요 없다.

검증점: suspicious 32개, correction 24개가 정확히 나온다.

## 5. EC meet-in-the-middle

알려진 digit의 기여를 먼저 합산한다.

```text
e = known + left + right  (mod n)
Q - known*G = left*G + right*G
```

registration의 encoded directory를 session id와 cookie로 해제하고 `RDIR5 → RSES5 → KCHK2`를 따라간다. 덤프에는 CRC가 유효하고 식별 필드가 없는 checkpoint가 context별로 8개 존재하므로 `KCHK2` 매직 검색만으로 활성 객체를 고를 수 없다. session pointer가 선택한 checkpoint에는 128-bit 경계 양쪽의 signed digit에 대한 두 modular 관계가 있다. 첫 관계로 각 절반의 두 pivot digit 조합을 제한하고, 두 번째 관계는 복구된 scalar를 독립적으로 검증한다. 남은 왼쪽 point를 테이블에 저장하고 오른쪽 후보마다 필요한 point를 조회해 `Q = eG`를 만족하는 유일한 scalar를 얻는다.

최종 고정 세트의 탐색량은 다음과 같다.

```text
left enumeration bound   419,904 states
right enumeration bound   62,208 states
stored left points        296,269 states
```

검증점: 복구한 scalar로 계산한 public point가 footer의 ephemeral point와 정확히 같다.

## 6. envelope와 region 복구

registration은 contract를 직접 가리키지 않는다. active session과 cookie로 `RDIR5` directory를 해제하고, encoded `RSES5` session과 `RVTB5` vtable을 거쳐 private mapping된 `RecordsArchiveService` image의 `RARC5` contract에 도달한다. directory/session/vtable CRC와 session/volume id뿐 아니라 292바이트 contract CRC, registration self-test, 문자열·binding pointer와 parser 함수가 같은 private image 범위에 있는지도 검증할 수 있다. contract의 parser 함수 포인터와 문자열 교차참조에서 footer TLV, HKDF salt/info 결합, manifest·region AAD/nonce 및 receipt 입력 순서를 복구한다.

복구한 scalar와 operator public point로 ECDH shared point를 계산한다. volume id, context와 file token에 묶인 HKDF로 KEK를 만들고 AES-KWP integrity를 검증하며 master key를 푼다.

master key로 encrypted manifest를 AES-GCM 복호화한다. `KMAP4`는 transaction id, generation 합계, logical region, generation, physical offset와 GCM tag를 담는다. generation 합계를 확인하고 96개 data region과 VHD footer region을 검증·재배치한다. manifest transaction id는 후속 journal과 같아야 한다.

검증점: AES-KWP integrity, manifest GCM tag와 총 97개 region tag가 모두 통과한다.

복구된 `BACKUP.LOG`는 ECDH envelope 수락, encrypted region map staging, journal flush와 orphaned receipt replay를 시간 순서대로 기록한다. `ARCHIVE.TXT`, `RETENT~1.TXT`, 보고서에는 같은 job id가, 로그·journal·보고서에는 같은 transaction id가 남아 있어 전반부의 키 계층과 후반부의 파일 복구가 하나의 Records Archive Service 장애 복구 흐름임을 교차 검증할 수 있다.

## 7. FAT16 journal

복구된 fixed VHD는 footer checksum과 원본 크기, MBR signature·파티션 경계, FAT16 boot signature와 동일한 두 FAT 사본을 독립적으로 검증할 수 있으며 사건 시각도 일관된다. root directory에서 삭제된 `*.PDF` entry와 `SYSJRN~1.BIN`을 찾는다. journal의 `KJNL5` 헤더는 record 크기, commit 크기, 각 항목 수와 transaction id를 스스로 기술하므로 별도 포맷 추측 없이 안전하게 경계를 계산할 수 있다. 그 뒤에는 같은 file id의 세 revision과 20개 decoy record가 있다.

각 revision은 record의 previous hash와 commit SHA-256을 검증한다. 가장 높은 유효 revision을 선택하고 sequence 순으로 7개 cluster fragment를 읽어 CRC32를 확인한다.

검증점: revision 3의 commit digest와 7개 fragment CRC가 모두 일치한다.

## 8. receipt와 플래그

재구성한 PDF에는 두 개의 revision이 있다. 두 번째 xref와 `/Prev`를 따라 incremental update의 `/RecordsRecovery` object를 찾고 ASCIIHex stream을 해제한다. 그 안의 `KRCPT3` receipt는 document id, 첫 PDF revision의 SHA-256과 sealed flag를 포함한다. document id의 하위 64비트가 삭제 FAT entry의 file id와 같은지 확인한 뒤 volume id, ephemeral point와 document id에 묶인 SHAKE-256 mask를 제거한다.

복원된 PDF는 case/job/transaction/volume, 생성 시각, journal replay 상태, revision·fragment 수와 무결성 상태를 담은 실제 복구 보고서 형태다. 마지막 문장 `Keys are temporary. Records are not.`은 제목, 문제 설명과 플래그를 하나의 주제로 마무리한다.

```text
SHA{wh3n_k3ys_v4n1sh_m3m0ry_r3m3mb3rs}
```

## 공정성 검토

- 모든 주요 단계는 다음 단계 전에 독립적인 무결성 검증값을 가진다.
- 하드코딩된 키 검색, 확률적 race, 서버 상태와 팀 간 간섭이 없다.
- 계산량은 생성 후 자동 범위 검사를 통과해야 한다.
- 핵심 EC 복구 이후 journal decoy는 20개로 제한한다.
- 문제 설명의 한 문장은 키 값이 아니라 소거된 표현이 분석 대상임만 알려준다.
- 참가자에게는 `KEYPSAKE.zip`의 세 아티팩트 외에는 배포하지 않는다.
- 의미 없는 control-flow flattening, packer, steganography, 비밀번호 추측, 추가 brute force와 대량 decoy는 사용하지 않는다.
