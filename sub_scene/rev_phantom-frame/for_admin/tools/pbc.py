#!/usr/bin/env python3
"""Private assembler helpers for the Afterimage bytecode container."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


OPS: dict[str, tuple[int, int]] = {
    "nop": (0x91, 2),
    "push_i8": (0x2D, 2),
    "push_i32": (0xC7, 8),
    "push_i47": (0x6F, 8),
    "push_const": (0x54, 4),
    "push_null": (0xB3, 2),
    "load": (0xA3, 2),
    "store": (0x18, 2),
    "dup": (0xEE, 2),
    "swap": (0x35, 2),
    "pop": (0x73, 2),
    "add": (0x4B, 2),
    "sub": (0xD2, 2),
    "xor": (0x0F, 2),
    "rol": (0xB8, 2),
    "eq": (0x65, 2),
    "lt": (0xF1, 2),
    "new_obj": (0x3C, 4),
    "get_field": (0x87, 2),
    "set_field": (0xDA, 2),
    "shape_guard": (0x26, 4),
    "new_array": (0xAC, 4),
    "get_elem": (0x59, 2),
    "set_elem": (0xE4, 2),
    "length_guard": (0x32, 4),
    "jump": (0x9E, 4),
    "jump_zero": (0x47, 4),
    "call": (0xBD, 4),
    "ret": (0x04, 2),
    "try_begin": (0x6A, 4),
    "try_end": (0xD7, 2),
    "throw": (0x21, 2),
    "catch": (0x8C, 2),
    "finally_end": (0xFA, 2),
    "loop_hint": (0x38, 4),
    "osr": (0xC1, 4),
    "deopt_hint": (0x7D, 2),
    "cap_public": (0x13, 2),
    "cap_derive": (0xA8, 2),
    "cap_check": (0x5E, 2),
    "vault_seal": (0xE1, 2),
    "trig_overflow": (0x42, 2),
    "trig_shape": (0x96, 4),
    "trig_bounds": (0x0B, 4),
    "trace": (0xCB, 4),
    "halt": (0x77, 2),
}

BRANCHES = {"jump", "jump_zero", "try_begin"}
PAIR8 = {"new_obj", "new_array", "trig_bounds"}
U16 = {
    "push_const",
    "shape_guard",
    "length_guard",
    "loop_hint",
    "osr",
    "trig_shape",
    "trace",
}


@dataclass(frozen=True)
class Label:
    name: str


@dataclass(frozen=True)
class Instruction:
    op: str
    args: tuple[object, ...] = ()


@dataclass
class Function:
    name: str
    arity: int
    locals: int
    max_stack: int
    flags: int = 0
    items: list[Label | Instruction] = field(default_factory=list)

    def emit(self, op: str, *args: object) -> "Function":
        if op not in OPS:
            raise ValueError(f"unknown opcode {op}")
        self.items.append(Instruction(op, args))
        return self

    def mark(self, name: str) -> "Function":
        self.items.append(Label(name))
        return self


@dataclass
class Constant:
    kind: int
    data: bytes


class Program:
    def __init__(self, entry: str = "main") -> None:
        self.entry = entry
        self.constants: list[Constant] = []
        self.functions: list[Function] = []

    def string(self, value: str) -> int:
        encoded = value.encode("utf-8")
        self.constants.append(Constant(1, encoded))
        return len(self.constants) - 1

    def blob(self, value: bytes) -> int:
        self.constants.append(Constant(2, bytes(value)))
        return len(self.constants) - 1

    def function(
        self, name: str, *, arity: int, locals: int, max_stack: int, flags: int = 0
    ) -> Function:
        if any(fn.name == name for fn in self.functions):
            raise ValueError(f"duplicate function {name}")
        fn = Function(name, arity, locals, max_stack, flags)
        self.functions.append(fn)
        return fn

    def assemble(self, opcode_map: dict[str, int] | None = None) -> bytes:
        if not self.functions or len(self.functions) > 48:
            raise ValueError("function limit")
        function_ids = {fn.name: i for i, fn in enumerate(self.functions)}
        if self.entry not in function_ids:
            raise ValueError("missing entry")
        encoded_functions: list[tuple[Function, bytes, int]] = []
        total_instructions = 0
        for fn in self.functions:
            labels: dict[str, int] = {}
            offset = 0
            for item in fn.items:
                if isinstance(item, Label):
                    if item.name in labels:
                        raise ValueError(f"duplicate label {item.name}")
                    labels[item.name] = offset
                else:
                    offset += OPS[item.op][1]
            code = bytearray()
            count = 0
            for item in fn.items:
                if isinstance(item, Label):
                    continue
                default_raw, size = OPS[item.op]
                raw = (opcode_map or {}).get(item.op, default_raw)
                here = len(code)
                code.append(raw)
                args = item.args
                if size == 2:
                    operand = 0
                    if item.op in {"push_i8", "load", "store", "get_field", "set_field"}:
                        if len(args) != 1:
                            raise ValueError(f"{item.op} needs one operand")
                        operand = int(args[0]) & 0xFF
                    elif args:
                        raise ValueError(f"{item.op} takes no operands")
                    code.append(operand)
                elif size == 8:
                    if len(args) != 1:
                        raise ValueError(f"{item.op} needs one operand")
                    value = int(args[0])
                    if item.op == "push_i32":
                        code.extend(struct.pack("<i", value))
                        code.extend(b"\x00\x00\x00")
                    else:
                        if not -(1 << 46) <= value < (1 << 46):
                            raise ValueError("i47 range")
                        code.extend((value & ((1 << 56) - 1)).to_bytes(7, "little"))
                else:
                    if item.op in BRANCHES:
                        if len(args) != 1 or str(args[0]) not in labels:
                            raise ValueError(f"unknown branch label in {fn.name}")
                        rel = labels[str(args[0])] - (here + size)
                        code.extend(struct.pack("<hB", rel, 0))
                    elif item.op == "call":
                        if len(args) != 2 or str(args[0]) not in function_ids:
                            raise ValueError("bad call")
                        code.extend(bytes((function_ids[str(args[0])], int(args[1]), 0)))
                    elif item.op in PAIR8:
                        if len(args) != 2:
                            raise ValueError(f"{item.op} needs two operands")
                        code.extend(bytes((int(args[0]) & 0xFF, int(args[1]) & 0xFF, 0)))
                    elif item.op in U16:
                        if len(args) != 1:
                            raise ValueError(f"{item.op} needs one operand")
                        code.extend(struct.pack("<HB", int(args[0]) & 0xFFFF, 0))
                    else:
                        raise ValueError(f"unhandled instruction {item.op}")
                count += 1
            encoded_functions.append((fn, bytes(code), count))
            total_instructions += count
        if total_instructions > 1024:
            raise ValueError("instruction limit")

        constants = bytearray()
        for const in self.constants:
            if len(const.data) > 512:
                raise ValueError("constant limit")
            constants.extend(struct.pack("<BBH", const.kind, 0, len(const.data)))
            constants.extend(const.data)
            while len(constants) % 4:
                constants.append(0)
        const_off = 32
        funcs_off = const_off + len(constants)
        code_off = funcs_off + len(encoded_functions) * 16
        function_table = bytearray()
        code = bytearray()
        for fn, body, count in encoded_functions:
            function_table.extend(
                struct.pack(
                    "<BBBBIIHH",
                    fn.arity,
                    fn.locals,
                    fn.max_stack,
                    fn.flags,
                    len(code),
                    len(body),
                    count,
                    0,
                )
            )
            code.extend(body)
        file_size = code_off + len(code) + 32
        header = struct.pack(
            "<4sHHHHIIIII",
            b"PPBC",
            1,
            len(self.functions),
            len(self.constants),
            function_ids[self.entry],
            total_instructions,
            const_off,
            funcs_off,
            code_off,
            file_size,
        )
        payload = header + constants + function_table + code
        if len(payload) + 32 != file_size or file_size > 16384:
            raise AssertionError("container layout")
        return payload + hashlib.sha256(payload).digest()

    def write(self, path: Path) -> None:
        path.write_bytes(self.assemble())


def add_nested_family(
    fn: Function,
    *,
    pad_calls: int,
    try_depth: int,
    trigger: str,
    trigger_args: Iterable[int] = (),
) -> None:
    for depth in range(try_depth):
        fn.emit("try_begin", f"handler_{depth}")
    for _ in range(pad_calls):
        fn.emit("call", "pad", 0).emit("pop")
    fn.emit("cap_public").emit("call", "guard", 1).emit("pop")
    if trigger == "trig_overflow":
        fn.emit("push_i32", (1 << 31) - 1).emit("push_i8", 1)
    fn.emit(trigger, *tuple(trigger_args))
    if trigger == "trig_overflow":
        fn.emit("pop")
    for _ in range(try_depth):
        fn.emit("try_end")
    fn.emit("push_null").emit("ret")
    # Every nested exceptional edge has its own small, equivalent landing pad.
    for depth in reversed(range(try_depth)):
        fn.mark(f"handler_{depth}").emit("catch").emit("pop")
        fn.emit("push_null").emit("ret")


def reference_program(
    pad_counts: tuple[int, int, int] = (14, 30, 46),
    local_slot: int = 13,
    loop_class: int = 0x351,
) -> Program:
    p = Program("main")
    message = p.string("archive:afterimage:open")
    main = p.function("main", arity=0, locals=16, max_stack=4)
    pad = p.function("pad", arity=0, locals=1, max_stack=1)
    guard = p.function("guard", arity=1, locals=14, max_stack=1)
    alpha = p.function("family_alpha", arity=0, locals=2, max_stack=4)
    beta = p.function("family_beta", arity=0, locals=2, max_stack=3)
    gamma = p.function("family_gamma", arity=0, locals=2, max_stack=3)

    pad.emit("push_null").emit("ret")
    if not 1 <= local_slot < 14:
        raise ValueError("collision local slot")
    guard.emit("load", 0).emit("store", local_slot).emit("load", local_slot)
    guard.emit("cap_check").emit("ret")
    add_nested_family(
        alpha, pad_calls=pad_counts[0], try_depth=2, trigger="trig_overflow"
    )
    add_nested_family(
        beta,
        pad_calls=pad_counts[1],
        try_depth=3,
        trigger="trig_shape",
        trigger_args=(2,),
    )
    add_nested_family(
        gamma,
        pad_calls=pad_counts[2],
        try_depth=4,
        trigger="trig_bounds",
        trigger_args=(2, 5),
    )

    main.emit("cap_public").emit("store", local_slot)
    main.emit("push_i8", 0).emit("store", 0).mark("outer")
    main.emit("loop_hint", loop_class).emit("load", 0).emit("push_i8", 1)
    main.emit("add").emit("store", 0).emit("osr", loop_class)
    main.emit("call", "family_alpha", 0).emit("pop")
    main.emit("call", "family_beta", 0).emit("pop")
    main.emit("call", "family_gamma", 0).emit("pop")
    main.emit("load", 0).emit("push_i8", 6).emit("lt")
    main.emit("jump_zero", "done").emit("jump", "outer")
    main.mark("done").emit("deopt_hint").emit("load", local_slot)
    main.emit("push_const", message).emit("vault_seal").emit("pop").emit("halt")
    return p


def safe_program() -> Program:
    p = Program("main")
    fn = p.function("main", arity=0, locals=1, max_stack=2)
    fn.emit("cap_public").emit("cap_check").emit("pop").emit("halt")
    return p
