#!/usr/bin/env python3
"""Shared private helper for extracting the generated opcode descriptor table."""

from __future__ import annotations

import struct
from pathlib import Path

from pbc import OPS


def recover_opcode_map(binary: Path) -> dict[str, int]:
    data = binary.read_bytes()
    names = list(OPS)
    sizes = [OPS[name][1] for name in names]
    ordinals = set(range(1, len(names) + 1))
    for offset in range(0, len(data) - 511, 64):
        words = struct.unpack_from("<256H", data, offset)
        used = [(raw, word) for raw, word in enumerate(words) if word]
        if len(used) != len(names) or {word & 0xFF for _, word in used} != ordinals:
            continue
        indexed = {word & 0xFF: (raw, word >> 8) for raw, word in used}
        if any(indexed[i + 1][1] != sizes[i] for i in range(len(names))):
            continue
        return {name: indexed[i + 1][0] for i, name in enumerate(names)}
    raise RuntimeError("opcode descriptor table not found")
