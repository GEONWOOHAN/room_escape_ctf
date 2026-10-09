#!/usr/bin/env python3

import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"


def parse_receipt(path: Path = USER / "receipt.bin") -> tuple[bytes, list[bytes], bytes]:
    data = path.read_bytes()
    if len(data) < 176 or data[:4] != b"PFRC":
        raise ValueError("bad receipt header")
    version, count, raw_len, reserved = struct.unpack_from("<HHII", data, 4)
    if version != 1 or count != 3 or raw_len != 152 or reserved:
        raise ValueError("non-canonical receipt")
    if len(data) != 16 + raw_len + 96 + 32 + 32:
        raise ValueError("receipt length")
    if hashlib.sha256(data[:-32]).digest() != data[-32:]:
        raise ValueError("receipt checksum")
    raw = data[16 : 16 + raw_len]
    if raw[:8] != b"PFTX\x01\x03\x00\x00":
        raise ValueError("transcript header")
    offset = 16 + raw_len
    seals = [data[offset + i * 32 : offset + (i + 1) * 32] for i in range(3)]
    structural = data[offset + 96 : offset + 128]
    return raw, seals, structural


def main() -> None:
    raw, seals, structural = parse_receipt()
    print(f"raw-transcript={len(raw)} bytes sha256={hashlib.sha256(raw).hexdigest()}")
    print(f"seals={len(seals)} structural={structural.hex()}")


if __name__ == "__main__":
    main()
