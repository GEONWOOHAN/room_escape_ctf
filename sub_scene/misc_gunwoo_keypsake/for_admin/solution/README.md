# KEYPSAKE

- 분야: Misc
- 태그: Forensics, Reverse Engineering, Cryptography
- 난이도: Medium
- 배포: 정적 파일, 서버 없음
- 플래그: `SHA{wh3n_k3ys_v4n1sh_m3m0ry_r3m3mb3rs}`

## 문제 설명

> A process memory dump and an encrypted backup volume were collected from a compromised file server.
>
> The key is gone. Its windowed representation is not.
>
> Recover the archived records from what remains.

참가자에게는 `for_user/KEYPSAKE.zip`만 제공한다. ZIP은 다음 세 파일만 포함한다.

```text
telemetry_provider.dll
RecordsArchiveService.dmp.zst
records_backup.vhd.kpsk
```

실행 가능한 ransomware와 서버 인스턴스는 없다. CTFd 및 리버스 프록시의 업로드 제한은 최소 128 MiB, 권장 256 MiB로 설정한다.

## 배포물 검증

CTFd에 올리기 전과 다시 내려받은 후 다음 해시가 일치해야 한다.

```text
SHA-256  1e52a32d4d2f64c2fe9b1df511118a1ca61f65c8162bb03245a9a65ee6f32d45
```

```powershell
Get-FileHash ..\..\for_user\KEYPSAKE.zip -Algorithm SHA256
```

## 공식 풀이 검증

ZIP을 별도 임시 디렉터리에 풀고 `RecordsArchiveService.dmp.zst`를 zstd로 해제한다.

```powershell
python -m pip install pycryptodome==3.23.0 zstandard==0.25.0
```

```powershell
python solution\solve.py `
  --memory <DIR>\RecordsArchiveService.dmp `
  --locked <DIR>\records_backup.vhd.kpsk `
  --output <DIR>\recovered.vhd `
  --pdf-output <DIR>\reconciliation_receipt.pdf `
  --mitm-cache <DIR>\mitm.cache
```

첫 캐시 생성과 전체 복구는 환경에 따라 약 1~3분, 캐시 재사용은 약 15~30초가 걸린다. 자세한 풀이 과정은 [writeup.md](./writeup.md)를 참고한다.
