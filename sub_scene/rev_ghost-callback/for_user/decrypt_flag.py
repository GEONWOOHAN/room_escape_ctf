#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent
from crypto_core import aead_decrypt, INSTALL_RECEIPT_MAGIC

AAD = b"ghost-callback-fleet-v6"
DEVICE_NAMES = ("a", "b", "c")
EXPECTED_TRANSCRIPT = 160


def parse_outputs(raw: bytes) -> dict[str, bytes]:
    if raw[:4] != b"GCO5":
        raise ValueError("callback output container mismatch")
    cursor = 4
    result = {}
    for name in DEVICE_NAMES:
        if cursor + 2 > len(raw):
            raise ValueError("callback output container truncated")
        length = struct.unpack_from("<H", raw, cursor)[0]
        cursor += 2
        if length != EXPECTED_TRANSCRIPT or cursor + length > len(raw):
            raise ValueError("device callback transcript length mismatch")
        result[name] = raw[cursor:cursor + length]
        cursor += length
    if cursor != len(raw):
        raise ValueError("callback output container has trailing data")
    return result


def install_receipt() -> bytes:
    receipt = (ROOT / ".stage/.install_receipt").read_bytes()
    if len(receipt) != 36 or not receipt.startswith(INSTALL_RECEIPT_MAGIC):
        raise ValueError("semantic install receipt mismatch")
    return receipt[4:]


def derive_key(calibration: bytes, outputs: dict[str, bytes]) -> bytes:
    material = bytearray(b"ghost-callback-fleet-receipt-v6\x00")
    material += hashlib.sha256(calibration).digest()
    material += install_receipt()
    for name in DEVICE_NAMES:
        firmware = (ROOT / ".stage" / "firmware" / f"firmware_{name}.bin").read_bytes()
        material += (
            name.encode() + hashlib.sha256(firmware).digest() + outputs[name]
        )
    return hashlib.blake2s(material).digest()


def main() -> None:
    calibration = (ROOT / ".stage/profiles/calibration.bin").read_bytes()
    outputs = parse_outputs((ROOT / "callback_outputs.bin").read_bytes())
    if len(calibration) != 64:
        raise ValueError("calibration data length mismatch")
    blob = (ROOT / "flag.enc").read_bytes()
    if len(blob) < 32 or blob[:4] != b"GCF6":
        raise ValueError("flag.enc format mismatch")
    plaintext = aead_decrypt(derive_key(calibration, outputs), blob[4:16], blob[16:], AAD)
    if not (plaintext.startswith(b"SHA{") and plaintext.endswith(b"}")):
        raise ValueError("decrypted data is not a flag")
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, UnicodeDecodeError) as error:
        print(f"복호화 실패: {error}", file=sys.stderr)
        raise SystemExit(1)
