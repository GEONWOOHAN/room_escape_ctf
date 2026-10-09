# DONOR 풀이

펌웨어는 64개의 16바이트 블록을 Rogaway의 XEX 형태로 암호화한다.

```text
delta_j = AES_K(N) * alpha^j          in GF(2^128)
C_i     = AES_K(P_i xor delta_j) xor delta_j
```

정상 구현이라면 블록 위치마다 고유한 지수 `j`를 사용해야 한다. 이 펌웨어는 주소 변환 비용을 줄이기 위해 다음 4비트 값만 지수로 사용한다.

```text
j(i) = ((5 * i) xor 3 xor (i >> 2)) & 15
```

따라서 64개 주소가 16개의 tweak class로 축소되고 각 class에는 정확히 네 주소가 존재한다. XEX는 데이터의 무결성을 인증하지 않으므로 같은 class의 유효 암호문을 다른 주소로 이식할 수 있다.

이 구성은 Phillip Rogaway의 XEX construction과 저장장치 기밀성 모드인 NIST SP 800-38E를 바탕으로 한다. SP 800-38E가 명시하듯 XTS-AES 자체는 데이터 또는 출처 인증을 제공하지 않는다.

- https://iacr.org/cryptodb/archive/2004/ASIACRYPT/426/426.pdf
- https://csrc.nist.gov/pubs/sp/800/38/e/final

## 정책 VM

빌드 6.2는 작은 32비트 stack VM으로 다음 네 프로그램을 실행한다.

- 축소 tweak exponent 분류
- PRNG 상태 전이
- 물리 레이아웃 seed 생성
- 정책 레코드 seed 생성

VM opcode와 바이트코드를 복원하면 epoch에 따른 tweak-class 보존 Fisher–Yates 순열 및 정책 레코드 위치를 계산할 수 있다.

## 상태형 체인

세 정책 레코드를 처음부터 모두 계산할 수는 없다. 첫 번째 maintenance donor와 target은 공개 epoch에서 결정되지만, 나머지 두 종류는 연결마다 무작위로 생성되는 routing nonce에 의존한다.

1. 시작 메시지의 session stamp에서 xorshift 전이와 홀수 곱셈 기반 affine permutation을 역산해 현재 연결의 epoch를 복구하고, `sheath`로 암호문을 받는다.
2. 복구한 epoch로 maintenance donor·target과 물리 위치를 계산한다.
3. 첫 번째 `transplant`로 maintenance 권한을 활성화한다.
4. `diagnose`를 호출해 현재 연결의 봉인된 routing capsule을 얻는다.
5. capsule의 xorshift 전이를 역산하고 epoch 기반 마스크를 제거해 route를 복구한 뒤 `epoch ^ rol32(route, 11) ^ 0x51a7c3d9`를 정책 VM에 입력해 나머지 두 donor·target을 계산한다.
6. 남은 두 번의 `transplant`로 UID와 vault capability를 이식한다.
7. `attest`를 실행해 플래그를 얻는다.

로컬 분석 키는 실제 서버의 연결별 무작위 키와 다르므로 서버 암호문 복호화에는 사용할 수 없다. 모든 암호문은 같은 연결에서 얻어야 하며, NVM write budget은 정확히 3회다.
