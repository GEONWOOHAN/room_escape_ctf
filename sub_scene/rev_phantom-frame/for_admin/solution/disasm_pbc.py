#!/usr/bin/env python3
"""Small recovered-format disassembler used by the official solve."""

from __future__ import annotations

import struct
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"
sys.path.insert(0, str(HERE))

from pbc import BRANCHES, OPS  # noqa: E402
from recover_format import recover_opcodes  # noqa: E402


def disassemble(path: Path) -> str:
    blob = path.read_bytes()
    if len(blob) < 64 or blob[:4] != b"PPBC":
        raise ValueError("not a PPBC file")
    _, version, fn_count, const_count, entry, total, const_off, funcs_off, code_off, size = struct.unpack_from(
        "<4sHHHHIIIII", blob, 0
    )
    if version != 1 or size != len(blob):
        raise ValueError("bad header")
    recovered = recover_opcodes()
    reverse = {raw: name for name, raw in recovered.items()}
    lines = [f"entry={entry} functions={fn_count} constants={const_count} instructions={total}"]
    for index in range(fn_count):
        arity, locals_, max_stack, flags, rel, length, count, _ = struct.unpack_from(
            "<BBBBIIHH", blob, funcs_off + index * 16
        )
        lines.append(
            f"\nfunction {index}: arity={arity} locals={locals_} stack={max_stack} count={count}"
        )
        pc = code_off + rel
        end = pc + length
        logical = 0
        while pc < end:
            raw = blob[pc]
            name = reverse.get(raw, f"raw_{raw:02x}")
            width = OPS[name][1] if name in OPS else 2
            operand = blob[pc + 1 : pc + width].hex()
            suffix = f" {operand}" if operand.strip("0") else ""
            if name in BRANCHES:
                delta = struct.unpack_from("<h", blob, pc + 1)[0]
                suffix = f" -> 0x{logical + width + delta:04x}"
            elif name == "call":
                suffix = f" f{blob[pc + 1]} argc={blob[pc + 2]}"
            lines.append(f"  {logical:04x}: {name}{suffix}")
            pc += width
            logical += width
    return "\n".join(lines)


def main() -> None:
    for sample in sorted((USER / "samples").glob("*.pbc")):
        print(f"===== {sample.name} =====")
        print(disassemble(sample))


if __name__ == "__main__":
    main()
