#!/usr/bin/env python3

import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"


def parse(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) != 96 or data[:4] != b"PPGO" or hashlib.sha256(data[:64]).digest() != data[64:]:
        raise ValueError("bad profile")
    return {
        "class": data[6],
        "reason": data[7],
        "allocation": data[8],
        "osr_threshold": data[9],
        "inline_budget": struct.unpack_from("<H", data, 10)[0],
        "warmup": struct.unpack_from("<H", data, 12)[0],
        "predicted_shape": struct.unpack_from("<I", data, 16)[0],
        "target_selector": data[20:52].hex(),
        "layout_seed": struct.unpack_from("<Q", data, 52)[0],
    }


def main() -> None:
    for name in ("alpha", "beta", "gamma"):
        values = parse(USER / "profiles" / f"{name}.pgo")
        print(name, values)


if __name__ == "__main__":
    main()
