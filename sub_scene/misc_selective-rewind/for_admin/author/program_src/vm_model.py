"""Bit-for-bit Python model of replay_vm, used for generation and verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Iterable

from isa import (
    CACHE_LINES,
    INSTRUCTION,
    LINE_COUNT,
    LINE_SIZE,
    MEM_SIZE,
    OP_ADD,
    OP_AND,
    OP_BARRIER,
    OP_CMP,
    OP_CMOV,
    OP_FLUSH,
    OP_HALT,
    OP_HASHSTEP,
    OP_JMP,
    OP_JNZ,
    OP_LOAD,
    OP_MEMCPY,
    OP_MOVI,
    OP_NOP,
    OP_OR,
    OP_ROL,
    OP_ROR,
    OP_STORE,
    OP_SUB,
    OP_XOR,
    PROGRAM_HEADER,
    Insn,
    join_u64,
)

MASK64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
MULTIPLIER = 0xD6E8FEB86659FD93


def rol64(value: int, amount: int) -> int:
    amount &= 63
    value &= MASK64
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def ror64(value: int, amount: int) -> int:
    amount &= 63
    value &= MASK64
    if amount == 0:
        return value
    return ((value >> amount) | (value << (64 - amount))) & MASK64


def hash_step(state: int, value: int, constant: int, rotation: int) -> int:
    mixed = (state + (value ^ constant) + GOLDEN) & MASK64
    right = (value + ((constant * MULTIPLIER) & MASK64)) & MASK64
    return rol64(mixed, rotation) ^ right


@dataclass
class CacheEntry:
    data: bytearray
    line: int = 0
    valid: bool = False
    dirty: bool = False
    stamp: int = 0


@dataclass(frozen=True)
class TraceRow:
    checkpoint: int
    pc: int
    operation: str
    line: int
    dirty_before: int
    dirty_after: int


class VM:
    def __init__(self, memory: bytes, instructions: list[Insn], entry: int = 0, max_steps: int = 20_000):
        if len(memory) != MEM_SIZE:
            raise ValueError("VM memory must be exactly 32 KiB")
        self.dram = bytearray(memory)
        self.instructions = instructions
        self.max_steps = max_steps
        self.regs = [0] * 16
        self.pc = entry
        self.checkpoint = 0
        self.steps = 0
        self.clock = 0
        self.zero = False
        self.carry = False
        self.negative = False
        self.cache = [CacheEntry(bytearray(LINE_SIZE)) for _ in range(CACHE_LINES)]
        self.faults_consumed = 0
        self.halted = False
        self.result_addr = 0
        self.trace: list[TraceRow] = []

    def _check_addr(self, addr: int, width: int = 1) -> None:
        if addr < 0 or width < 1 or addr + width > MEM_SIZE:
            raise ValueError(f"memory access outside VM: {addr:#x}+{width}")

    def _find(self, line: int) -> CacheEntry | None:
        for entry in self.cache:
            if entry.valid and entry.line == line:
                return entry
        return None

    def _writeback(self, entry: CacheEntry) -> None:
        if entry.valid and entry.dirty:
            start = entry.line * LINE_SIZE
            self.dram[start:start + LINE_SIZE] = entry.data
            entry.dirty = False

    def _get(self, line: int) -> CacheEntry:
        if not 0 <= line < LINE_COUNT:
            raise ValueError("invalid cache line")
        self.clock += 1
        hit = self._find(line)
        if hit is not None:
            hit.stamp = self.clock
            return hit
        victim = next((entry for entry in self.cache if not entry.valid), None)
        if victim is None:
            victim = min(self.cache, key=lambda entry: entry.stamp)
            self._writeback(victim)
        start = line * LINE_SIZE
        victim.data[:] = self.dram[start:start + LINE_SIZE]
        victim.line = line
        victim.valid = True
        victim.dirty = False
        victim.stamp = self.clock
        return victim

    def read(self, addr: int, width: int) -> int:
        self._check_addr(addr, width)
        if addr // LINE_SIZE != (addr + width - 1) // LINE_SIZE:
            return sum(self.read(addr + i, 1) << (8 * i) for i in range(width))
        entry = self._get(addr // LINE_SIZE)
        offset = addr % LINE_SIZE
        return int.from_bytes(entry.data[offset:offset + width], "little")

    def write(self, addr: int, value: int, width: int) -> None:
        self._check_addr(addr, width)
        if addr // LINE_SIZE != (addr + width - 1) // LINE_SIZE:
            for i in range(width):
                self.write(addr + i, value >> (8 * i), 1)
            return
        entry = self._get(addr // LINE_SIZE)
        offset = addr % LINE_SIZE
        entry.data[offset:offset + width] = (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
        entry.dirty = True

    def flush(self, line: int) -> None:
        entry = self._find(line)
        if entry is not None:
            self._writeback(entry)

    def apply_fault(self, line: int) -> None:
        entry = self._find(line)
        if entry is not None and entry.dirty:
            entry.valid = False
            entry.dirty = False

    def is_dirty(self, line: int) -> bool:
        entry = self._find(line)
        return bool(entry is not None and entry.dirty)

    def dirty_lines(self) -> set[int]:
        return {entry.line for entry in self.cache if entry.valid and entry.dirty}

    @staticmethod
    def _width(flags: int) -> int:
        width = flags & 0x0F
        if width not in (1, 2, 4, 8):
            raise ValueError(f"unsupported access width {width}")
        return width

    @staticmethod
    def _primary_line(insn: Insn) -> int:
        if insn.opcode in (OP_LOAD, OP_STORE, OP_HASHSTEP, OP_FLUSH):
            return insn.addr // LINE_SIZE
        if insn.opcode == OP_MEMCPY:
            return insn.addr // LINE_SIZE
        return -1

    def _execute(self, insn: Insn) -> tuple[int, bool]:
        op = insn.opcode
        next_pc = self.pc + 1
        request_halt = False
        if op == OP_MOVI:
            self.regs[insn.dst & 15] = join_u64(insn.imm, insn.aux)
        elif op == OP_LOAD:
            width = self._width(insn.flags)
            self.regs[insn.dst & 15] = self.read(insn.addr, width)
        elif op == OP_STORE:
            width = self._width(insn.flags)
            self.write(insn.addr, self.regs[insn.src & 15], width)
        elif op in (OP_ADD, OP_SUB, OP_XOR, OP_AND, OP_OR):
            dst, src = insn.dst & 15, insn.src & 15
            left, right = self.regs[dst], self.regs[src]
            if op == OP_ADD:
                total = left + right
                self.regs[dst] = total & MASK64
                self.carry = total > MASK64
            elif op == OP_SUB:
                self.regs[dst] = (left - right) & MASK64
                self.carry = left >= right
            elif op == OP_XOR:
                self.regs[dst] = left ^ right
            elif op == OP_AND:
                self.regs[dst] = left & right
            else:
                self.regs[dst] = left | right
            self.zero = self.regs[dst] == 0
            self.negative = bool(self.regs[dst] >> 63)
        elif op == OP_ROL:
            self.regs[insn.dst & 15] = rol64(self.regs[insn.dst & 15], insn.imm)
        elif op == OP_ROR:
            self.regs[insn.dst & 15] = ror64(self.regs[insn.dst & 15], insn.imm)
        elif op == OP_HASHSTEP:
            constant = join_u64(insn.imm, insn.aux)
            old = self.read(insn.addr, 8)
            value = self.regs[insn.src & 15]
            self.write(insn.addr, hash_step(old, value, constant, insn.flags & 63), 8)
        elif op == OP_FLUSH:
            self._check_addr(insn.addr)
            self.flush(insn.addr // LINE_SIZE)
        elif op == OP_BARRIER:
            mask, wanted = insn.imm, insn.aux
            for entry in self.cache:
                if entry.valid and entry.dirty and (entry.line & mask) == wanted:
                    self._writeback(entry)
        elif op == OP_CMP:
            left = self.regs[insn.dst & 15]
            right = self.regs[insn.src & 15]
            value = (left - right) & MASK64
            self.zero = value == 0
            self.carry = left >= right
            self.negative = bool(value >> 63)
        elif op == OP_CMOV:
            condition = (not self.zero) if (insn.flags & 1) else self.zero
            if condition:
                self.regs[insn.dst & 15] = self.regs[insn.src & 15]
        elif op == OP_JMP:
            next_pc = insn.imm
        elif op == OP_JNZ:
            if not self.zero:
                next_pc = insn.imm
        elif op == OP_MEMCPY:
            self._check_addr(insn.imm, insn.aux)
            self._check_addr(insn.addr, insn.aux)
            temporary = bytes(self.read(insn.imm + i, 1) for i in range(insn.aux))
            for i, value in enumerate(temporary):
                self.write(insn.addr + i, value, 1)
        elif op == OP_HALT:
            self._check_addr(insn.addr, 56)
            self.result_addr = insn.addr
            request_halt = True
        elif op == OP_NOP:
            pass
        else:
            raise ValueError(f"unknown opcode {op:#x} at pc {self.pc}")
        return next_pc, request_halt

    def run(
        self,
        faults: Iterable[tuple[int, int]] = (),
        *,
        record_trace: bool = False,
        on_checkpoint: Callable[["VM"], None] | None = None,
    ) -> dict[str, int | bool | str]:
        fault_list = list(faults)
        fault_index = 0
        while not self.halted and self.steps < self.max_steps:
            if not 0 <= self.pc < len(self.instructions):
                raise ValueError(f"pc outside program: {self.pc}")
            current_pc = self.pc
            insn = self.instructions[current_pc]
            primary = self._primary_line(insn)
            dirty_before = int(primary >= 0 and self.is_dirty(primary))
            next_pc, request_halt = self._execute(insn)
            dirty_after = int(primary >= 0 and self.is_dirty(primary))
            self.steps += 1
            self.checkpoint += 1
            if record_trace:
                self.trace.append(
                    TraceRow(
                        checkpoint=self.checkpoint,
                        pc=PROGRAM_HEADER.size + current_pc * INSTRUCTION.size,
                        operation=insn.name,
                        line=primary,
                        dirty_before=dirty_before,
                        dirty_after=dirty_after,
                    )
                )
            if on_checkpoint is not None:
                on_checkpoint(self)
            while fault_index < len(fault_list) and fault_list[fault_index][0] == self.checkpoint:
                self.apply_fault(fault_list[fault_index][1])
                self.faults_consumed += 1
                fault_index += 1
            self.pc = next_pc
            if request_halt:
                self.halted = True
        return self.result()

    def logical_memory(self) -> bytes:
        snapshot = bytearray(self.dram)
        for entry in self.cache:
            if entry.valid:
                start = entry.line * LINE_SIZE
                snapshot[start:start + LINE_SIZE] = entry.data
        return bytes(snapshot)

    def result(self) -> dict[str, int | bool | str]:
        if self.halted:
            values = [self.read(self.result_addr + i * 8, 8) for i in range(7)]
        else:
            values = [0, 0, 0, 0, 0, 0, 1]
        authenticated, uid, generation, reason, lease, audit, recomputed = values
        audit_valid = audit == recomputed
        digest = hashlib.sha256(self.logical_memory()).hexdigest()
        return {
            "halted": self.halted,
            "authenticated": authenticated,
            "uid": uid,
            "generation": generation,
            "reason": reason,
            "lease": lease,
            "audit_valid": audit_valid,
            "faults_consumed": self.faults_consumed,
            "success": bool(
                self.halted
                and authenticated == 1
                and uid == 0
                and generation == 7
                and reason == 0
                and lease == 1
                and audit_valid
                and self.faults_consumed == 5
            ),
            "digest": digest,
        }


def collect_faultable(
    memory: bytes,
    instructions: list[Insn],
    relevant_lines: set[int] | None = None,
    *,
    entry: int = 0,
    max_steps: int = 20_000,
) -> list[tuple[int, int]]:
    events: set[tuple[int, int]] = set()

    def observe(vm: VM) -> None:
        for line in vm.dirty_lines():
            if relevant_lines is None or line in relevant_lines:
                events.add((vm.checkpoint, line))

    VM(memory, instructions, entry, max_steps).run(on_checkpoint=observe)
    return sorted(events)
