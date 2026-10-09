"""Backward qword-level dependency slice from the HALT result object."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Opcodes recovered from the fixed-width public program format. Keeping these
# values here makes the explanatory slicer independent of author/program_src.
LINE_SIZE = 64
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
OP_CMOV = 0xAB
OP_MEMCPY = 0xD5
OP_HALT = 0xE7


@dataclass(frozen=True)
class SliceResult:
    result_addr: int
    memory_words: frozenset[int]
    lines: frozenset[int]
    instruction_indexes: frozenset[int]


def backward_slice(instructions: list[Any]) -> SliceResult:
    halt_indexes = [i for i, insn in enumerate(instructions) if insn.opcode == OP_HALT]
    if len(halt_indexes) != 1:
        raise ValueError("the solver expects one HALT")
    result_addr = instructions[halt_indexes[0]].addr
    live_memory = {result_addr + offset for offset in range(0, 56, 8)}
    all_memory = set(live_memory)
    live_registers: set[int] = set()
    selected: set[int] = {halt_indexes[0]}

    for index in range(halt_indexes[0] - 1, -1, -1):
        insn = instructions[index]
        op = insn.opcode
        dst, src = insn.dst & 15, insn.src & 15
        relevant = False
        if op == OP_STORE and insn.addr in live_memory:
            live_memory.remove(insn.addr)
            live_registers.add(src)
            relevant = True
        elif op == OP_LOAD and dst in live_registers:
            live_registers.remove(dst)
            live_memory.add(insn.addr)
            all_memory.add(insn.addr)
            relevant = True
        elif op == OP_MOVI and dst in live_registers:
            live_registers.remove(dst)
            relevant = True
        elif op in (OP_ADD, OP_SUB, OP_XOR, OP_AND, OP_OR) and dst in live_registers:
            # These operations read the old destination and the source.
            live_registers.add(src)
            relevant = True
        elif op in (OP_ROL, OP_ROR) and dst in live_registers:
            relevant = True
        elif op == OP_CMOV and dst in live_registers:
            live_registers.add(src)
            relevant = True
        elif op == OP_HASHSTEP and insn.addr in live_memory:
            # HASHSTEP updates a memory word from its old value and one register.
            live_registers.add(src)
            all_memory.add(insn.addr)
            relevant = True
        elif op == OP_MEMCPY:
            for offset in range(0, insn.aux, 8):
                destination = insn.addr + offset
                if destination in live_memory:
                    live_memory.remove(destination)
                    source = insn.imm + offset
                    live_memory.add(source)
                    all_memory.add(source)
                    all_memory.add(destination)
                    relevant = True
        if relevant:
            selected.add(index)
            all_memory.update(live_memory)

    lines = {address // LINE_SIZE for address in all_memory}
    return SliceResult(
        result_addr=result_addr,
        memory_words=frozenset(all_memory),
        lines=frozenset(lines),
        instruction_indexes=frozenset(selected),
    )
