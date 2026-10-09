#!/usr/bin/env python3

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ADMIN = HERE.parent
sys.path.insert(0, str(HERE))

from pbc import reference_program  # noqa: E402
from recover_map import recover_opcode_map  # noqa: E402


def main() -> None:
    seed = int((ADMIN / "instance.seed").read_text(encoding="ascii").strip(), 0)
    local_slot = 8 + seed % 6
    loop_class = ((seed >> 17) ^ seed) & 0xFFFF or 1
    opcode_map = recover_opcode_map(ADMIN.parent / "for_user" / "phantom_vm")
    encoded = reference_program(
        local_slot=local_slot, loop_class=loop_class
    ).assemble(opcode_map)
    (ADMIN / "solution" / "reference_candidate.pbc").write_bytes(encoded)
    print(f"private reference candidate built ({len(encoded)} bytes)")


if __name__ == "__main__":
    main()
