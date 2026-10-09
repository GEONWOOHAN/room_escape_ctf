#!/usr/bin/env python3
"""Locate stable compiler data without relying on symbols or addresses."""

from pathlib import Path

from recover_format import recover_opcodes

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"


def main() -> None:
    binary = (USER / "phantom_vm").read_bytes()
    recovered = recover_opcodes()
    print(f"runner-size={len(binary)}")
    print(f"decoded-opcodes={len(recovered)}")
    # x86 encoding for `and reg, 0xf` occurs in the shortened frame-id path.
    candidates = sum(binary.count(pattern) for pattern in (b"\x83\xe0\x0f", b"\x83\xe1\x0f"))
    print(f"low4-mask machine-code candidates={candidates}")


if __name__ == "__main__":
    main()
