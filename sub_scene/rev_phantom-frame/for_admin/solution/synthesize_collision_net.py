#!/usr/bin/env python3
"""Construct the shared OSR loop and the three bounded wrapper families."""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pbc import Program, reference_program  # noqa: E402
from parse_profiles import parse, USER  # noqa: E402


def synthesize(local_slot: int = 13) -> Program:
    pad_counts: list[int] = []
    for name in ("alpha", "beta", "gamma"):
        profile = parse(USER / "profiles" / f"{name}.pgo")
        budget = int(profile["inline_budget"])
        frames = [
            frame
            for frame in range(2, 1024)
            if (frame & 0xF) == 1 and frame - 1 <= budget
        ]
        if not frames:
            raise RuntimeError(f"no collision fits {name} inline budget")
        # The largest fitting class keeps the three profile families distinct.
        pad_counts.append(max(frames) - 3)
    snapshot = (USER / "runtime.snap").read_bytes()
    if len(snapshot) < 16 or snapshot[:4] != b"PSNP":
        raise RuntimeError("invalid runtime snapshot")
    seed = int.from_bytes(snapshot[8:16], "little")
    loop_class = ((seed >> 17) ^ seed) & 0xFFFF or 1
    return reference_program(
        tuple(pad_counts), local_slot=local_slot, loop_class=loop_class
    )


if __name__ == "__main__":
    program = synthesize()
    print(f"functions={len(program.functions)}")
    counts = [
        sum(1 for item in fn.items if getattr(item, "op", None) == "call") - 1
        for fn in program.functions[3:6]
    ]
    print("padding-call counts=" + ",".join(map(str, counts)))
