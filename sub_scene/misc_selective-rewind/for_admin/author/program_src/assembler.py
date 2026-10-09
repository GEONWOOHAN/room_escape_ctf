"""Small assembler used by the deterministic challenge generator."""

from __future__ import annotations

from dataclasses import dataclass, field

from isa import (
    Insn,
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
    split_u64,
)


@dataclass
class Assembler:
    instructions: list[Insn] = field(default_factory=list)

    @property
    def checkpoint(self) -> int:
        return len(self.instructions)

    def emit(self, opcode: int, **kwargs: int) -> int:
        self.instructions.append(Insn(opcode=opcode, **kwargs))
        return len(self.instructions)

    def movi(self, dst: int, value: int) -> int:
        low, high = split_u64(value)
        return self.emit(OP_MOVI, dst=dst, imm=low, aux=high)

    def load(self, dst: int, addr: int) -> int:
        return self.emit(OP_LOAD, flags=8, dst=dst, addr=addr)

    def store(self, src: int, addr: int) -> int:
        return self.emit(OP_STORE, flags=8, src=src, addr=addr)

    def add(self, dst: int, src: int) -> int:
        return self.emit(OP_ADD, dst=dst, src=src)

    def sub(self, dst: int, src: int) -> int:
        return self.emit(OP_SUB, dst=dst, src=src)

    def xor(self, dst: int, src: int) -> int:
        return self.emit(OP_XOR, dst=dst, src=src)

    def and_(self, dst: int, src: int) -> int:
        return self.emit(OP_AND, dst=dst, src=src)

    def or_(self, dst: int, src: int) -> int:
        return self.emit(OP_OR, dst=dst, src=src)

    def rol(self, dst: int, amount: int) -> int:
        return self.emit(OP_ROL, dst=dst, imm=amount)

    def ror(self, dst: int, amount: int) -> int:
        return self.emit(OP_ROR, dst=dst, imm=amount)

    def hashstep(self, addr: int, src: int, constant: int, rotation: int) -> int:
        low, high = split_u64(constant)
        return self.emit(
            OP_HASHSTEP,
            flags=rotation & 63,
            src=src,
            imm=low,
            addr=addr,
            aux=high,
        )

    def flush(self, addr: int) -> int:
        return self.emit(OP_FLUSH, addr=addr)

    def barrier(self, mask: int, value: int) -> int:
        return self.emit(OP_BARRIER, imm=mask, aux=value)

    def cmp(self, dst: int, src: int) -> int:
        return self.emit(OP_CMP, dst=dst, src=src)

    def cmov(self, dst: int, src: int, when_not_zero: bool = False) -> int:
        return self.emit(OP_CMOV, flags=int(when_not_zero), dst=dst, src=src)

    def jmp(self, target: int) -> int:
        return self.emit(OP_JMP, imm=target)

    def jnz(self, target: int) -> int:
        return self.emit(OP_JNZ, imm=target)

    def memcpy(self, dst_addr: int, src_addr: int, length: int) -> int:
        return self.emit(OP_MEMCPY, addr=dst_addr, imm=src_addr, aux=length)

    def nop(self) -> int:
        return self.emit(OP_NOP)

    def halt(self, result_addr: int) -> int:
        return self.emit(OP_HALT, addr=result_addr)

