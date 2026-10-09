#!/usr/bin/env python3

import hashlib
import hmac
import struct
from pathlib import Path

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

from parse_receipt import parse_receipt

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"


def hkdf(raw: bytes, seals: list[bytes], salt: bytes) -> bytes:
    prk = hmac.new(salt, raw + b"".join(seals), hashlib.sha256).digest()
    return hmac.new(prk, b"phantom-frame-v1\x01", hashlib.sha256).digest()


def decrypt() -> bytes:
    raw, seals, _ = parse_receipt()
    commitment = (USER / "transcript.commit").read_bytes()
    if hashlib.sha256(raw).digest() != commitment:
        raise ValueError("commitment mismatch")
    encrypted = (USER / "flag.enc").read_bytes()
    if len(encrypted) < 88 or encrypted[:4] != b"PFEN":
        raise ValueError("flag header")
    version, flags, length, reserved = struct.unpack_from("<HHII", encrypted, 4)
    if version != 1 or flags or reserved or len(encrypted) != 72 + length:
        raise ValueError("flag encoding")
    salt = encrypted[16:48]
    nonce = encrypted[48:72]
    key = hkdf(raw, seals, salt)
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        encrypted[72:], encrypted[:72], nonce, key
    )


def main() -> None:
    print(decrypt().decode("ascii"))


if __name__ == "__main__":
    main()
