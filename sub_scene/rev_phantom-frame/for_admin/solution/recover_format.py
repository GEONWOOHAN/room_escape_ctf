#!/usr/bin/env python3
"""Recover the per-instance raw opcode permutation from the stripped runner."""

from __future__ import annotations

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"
sys.path.insert(0, str(HERE))

from pbc import OPS  # noqa: E402
from recover_map import recover_opcode_map  # noqa: E402


def recover_opcodes(binary: Path = USER / "phantom_vm") -> dict[str, int]:
    return recover_opcode_map(binary)


def main() -> None:
    recovered = recover_opcodes()
    for name, raw in recovered.items():
        print(f"{name:16s} 0x{raw:02x} size={OPS[name][1]}")


if __name__ == "__main__":
    main()
