"""Binary formats and ISA constants shared by the author-side tools."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

LINE_COUNT = 512
LINE_SIZE = 64
CACHE_LINES = 32
MEM_SIZE = LINE_COUNT * LINE_SIZE
PROGRAM_MAGIC = b"SRWPROG1"
PROGRAM_VERSION = 1
PROGRAM_HEADER = struct.Struct("<8sIIIIQ")
INSTRUCTION = struct.Struct("<BBBBIII")
IMAGE_MAGIC = b"REWIND01"
IMAGE_HEADER = struct.Struct("<8sIIQ")

OP_MOVI = 0x11
OP_LOAD = 0x27
OP_STORE = 0x39
OP_ADD = 0x44
OP_SUB = 0x4B
OP_XOR = 0x53
OP_AND = 0x5A
OP_OR = 0x5F
OP_ROL = 0x61
OP_ROR = 0x68
OP_HASHSTEP = 0x72
OP_FLUSH = 0x80
OP_BARRIER = 0x91
OP_CMP = 0xA3
OP_CMOV = 0xAB
OP_JMP = 0xB7
OP_JNZ = 0xC2
OP_MEMCPY = 0xD5
OP_HALT = 0xE7
OP_NOP = 0xF1

OP_NAMES = {
    OP_MOVI: "MOVI",
    OP_LOAD: "LOAD",
    OP_STORE: "STORE",
    OP_ADD: "ADD",
    OP_SUB: "SUB",
    OP_XOR: "XOR",
    OP_AND: "AND",
    OP_OR: "OR",
    OP_ROL: "ROL",
    OP_ROR: "ROR",
    OP_HASHSTEP: "HASHSTEP",
    OP_FLUSH: "FLUSH",
    OP_BARRIER: "BARRIER",
    OP_CMP: "CMP",
    OP_CMOV: "CMOV",
    OP_JMP: "JMP",
    OP_JNZ: "JNZ",
    OP_MEMCPY: "MEMCPY",
    OP_HALT: "HALT",
    OP_NOP: "NOP",
}


@dataclass(frozen=True)
class Insn:
    opcode: int
    flags: int = 0
    dst: int = 0
    src: int = 0
    imm: int = 0
    addr: int = 0
    aux: int = 0

    def pack(self) -> bytes:
        return INSTRUCTION.pack(
            self.opcode & 0xFF,
            self.flags & 0xFF,
            self.dst & 0xFF,
            self.src & 0xFF,
            self.imm & 0xFFFFFFFF,
            self.addr & 0xFFFFFFFF,
            self.aux & 0xFFFFFFFF,
        )

    @property
    def name(self) -> str:
        return OP_NAMES.get(self.opcode, f"OP_{self.opcode:02x}")


def split_u64(value: int) -> tuple[int, int]:
    value &= (1 << 64) - 1
    return value & 0xFFFFFFFF, value >> 32


def join_u64(low: int, high: int) -> int:
    return (low & 0xFFFFFFFF) | ((high & 0xFFFFFFFF) << 32)


def read_program(path: str | Path) -> tuple[dict[str, int], list[Insn]]:
    raw = Path(path).read_bytes()
    if len(raw) < PROGRAM_HEADER.size + 32:
        raise ValueError("program is truncated")
    body, claimed = raw[:-32], raw[-32:]
    if hashlib.sha256(body).digest() != claimed:
        raise ValueError("program checksum mismatch")
    magic, version, count, entry, max_steps, seed = PROGRAM_HEADER.unpack_from(body)
    if magic != PROGRAM_MAGIC or version != PROGRAM_VERSION:
        raise ValueError("unsupported program")
    expected = PROGRAM_HEADER.size + count * INSTRUCTION.size
    if len(body) != expected:
        raise ValueError("invalid program length")
    insns = [Insn(*INSTRUCTION.unpack_from(body, PROGRAM_HEADER.size + i * 16)) for i in range(count)]
    return {
        "version": version,
        "count": count,
        "entry": entry,
        "max_steps": max_steps,
        "seed": seed,
    }, insns


def write_program(path: str | Path, insns: list[Insn], seed: int, entry: int = 0) -> None:
    max_steps = max(len(insns) + 16, 20_000)
    body = PROGRAM_HEADER.pack(
        PROGRAM_MAGIC, PROGRAM_VERSION, len(insns), entry, max_steps, seed
    ) + b"".join(insn.pack() for insn in insns)
    Path(path).write_bytes(body + hashlib.sha256(body).digest())


def read_image(path: str | Path) -> tuple[int, bytes]:
    raw = Path(path).read_bytes()
    expected = IMAGE_HEADER.size + MEM_SIZE + 32
    if len(raw) != expected:
        raise ValueError("invalid image length")
    body, claimed = raw[:-32], raw[-32:]
    if hashlib.sha256(body).digest() != claimed:
        raise ValueError("image checksum mismatch")
    magic, count, size, seed = IMAGE_HEADER.unpack_from(body)
    if magic != IMAGE_MAGIC or count != LINE_COUNT or size != LINE_SIZE:
        raise ValueError("unsupported image")
    return seed, body[IMAGE_HEADER.size:]


def write_image(path: str | Path, memory: bytes, seed: int) -> None:
    if len(memory) != MEM_SIZE:
        raise ValueError("memory image must be exactly 32 KiB")
    body = IMAGE_HEADER.pack(IMAGE_MAGIC, LINE_COUNT, LINE_SIZE, seed) + memory
    Path(path).write_bytes(body + hashlib.sha256(body).digest())


def canonical_plan(faults: list[tuple[int, int]]) -> bytes:
    if len(faults) != 5:
        raise ValueError("canonical plans contain exactly five faults")
    out = bytearray(b"PLN3")
    previous = -1
    for checkpoint, line in faults:
        if not (1 <= checkpoint <= 0xFFFFFFFF and 0 <= line < LINE_COUNT):
            raise ValueError("fault outside canonical range")
        if checkpoint <= previous:
            raise ValueError("fault checkpoints are not strictly increasing")
        out += struct.pack("<IH", checkpoint, line)
        previous = checkpoint
    return bytes(out)
