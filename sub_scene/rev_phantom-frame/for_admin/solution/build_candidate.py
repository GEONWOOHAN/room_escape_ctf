#!/usr/bin/env python3
"""Build the semantic collision net; no candidate byte string is embedded."""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"
sys.path.insert(0, str(HERE))

from recover_format import recover_opcodes  # noqa: E402
from synthesize_collision_net import synthesize  # noqa: E402


def main() -> None:
    opcode_map = recover_opcodes()
    encoded = synthesize().assemble(opcode_map)
    (HERE / "reference_candidate.pbc").write_bytes(encoded)
    (USER / "candidate.pbc").write_bytes(encoded)
    print(f"candidate.pbc built ({len(encoded)} bytes)")


if __name__ == "__main__":
    main()
