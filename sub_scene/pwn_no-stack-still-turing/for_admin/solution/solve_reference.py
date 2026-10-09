#!/usr/bin/env python3
"""Player-side reference solve for the fixed NSST v3 handout.

The addresses and function IDs below are the result of disassembling target.elf,
walking memory.img, and comparing the public goal/vector semantics. This file
imports no author implementation and verifies its payload with the distributed
native checker in a disposable handout copy.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


START_PC = 0x0760
KEY_DISPLACEMENT = 0
COOKIE = 0xC3D2E1F0

# (node offset in memory.img, replacement target function ID)
REPLACEMENTS = (
    (0x0270, 221),
    (0x0D80, 174),
    (0x0F20, 201),
    (0x0970, 355),
    (0x0E50, 29),
    (0x0830, 207),
)


def locate_handout() -> Path:
    configured = os.environ.get("NSST_HANDOUT_DIR")
    candidates = [Path(configured)] if configured else [
        Path.cwd(),
        Path(__file__).resolve().parents[1],
        Path(__file__).resolve().parents[1].parent / "for_user",
    ]
    required = (
        "checker", "flag.enc", "goal.pcode", "memory.img",
        "payload.template.bin", "target.elf", "vectors.bin",
    )
    for candidate in candidates:
        resolved = candidate.resolve()
        if all((resolved / name).is_file() for name in required):
            return resolved
    raise RuntimeError("run from a no-stack-still-turing for_user directory")


def rol32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def build_payload(template_path: Path, memory_path: Path) -> bytes:
    payload = bytearray(template_path.read_bytes())
    memory = memory_path.read_bytes()
    if len(payload) != 0xB8 or payload[:4] != b"NSST":
        raise ValueError("unexpected payload template")

    struct.pack_into("<I", payload, 0x18, START_PC)
    struct.pack_into("<I", payload, 0x24, KEY_DISPLACEMENT)

    for replacement_no, (node_offset, new_function_id) in enumerate(REPLACEMENTS):
        _old_id, argument_offset, next_offset, _old_guard = struct.unpack_from(
            "<4I", memory, node_offset
        )
        new_guard = rol32(
            new_function_id ^ argument_offset ^ next_offset ^ COOKIE, 7
        )
        for write_no, (offset, value) in enumerate(
            ((node_offset, new_function_id), (node_offset + 12, new_guard))
        ):
            record = 2 + replacement_no * 2 + write_no
            struct.pack_into(
                "<BBHII", payload, 0x10 + record * 12,
                2, 0, offset, 0, value,
            )
    return bytes(payload)


def solve() -> str:
    handout = locate_handout()
    payload = build_payload(
        handout / "payload.template.bin", handout / "memory.img"
    )
    with tempfile.TemporaryDirectory(prefix="nsst-reference-") as directory:
        work = Path(directory) / "handout"
        work.mkdir()
        for name in (
            "checker", "flag.enc", "goal.pcode", "memory.img",
            "payload.template.bin", "target.elf", "vectors.bin",
        ):
            shutil.copy2(handout / name, work / name)
        (work / "payload.bin").write_bytes(payload)
        completed = subprocess.run(
            [str(work / "checker")],
            cwd=work,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
        )
    output = completed.stdout.strip()
    if completed.returncode or not (output.startswith("SHA{") and output.endswith("}")):
        raise RuntimeError(completed.stderr.strip() or output or "native checker rejected payload")
    return output


def main() -> None:
    print(solve())


if __name__ == "__main__":
    main()
