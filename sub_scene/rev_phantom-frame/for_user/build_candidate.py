#!/usr/bin/env python3
"""Starter assembler for Phantom Frame.

The VM/container boilerplate is intentionally provided.  Recover the three
padding counts from the frame-state collision and pass them with --pads.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass, field


OPS = {
    "push_i8": (217, 2), "push_i32": (93, 8),
    "push_const": (138, 4), "push_null": (118, 2),
    "load": (43, 2), "store": (97, 2), "pop": (94, 2),
    "add": (148, 2), "lt": (90, 2), "call": (208, 4),
    "jump": (3, 4), "jump_zero": (194, 4),
    "ret": (48, 2), "try_begin": (166, 4),
    "try_end": (60, 2), "catch": (230, 2),
    "loop_hint": (227, 4), "osr": (169, 4),
    "deopt_hint": (231, 2), "cap_public": (136, 2),
    "cap_check": (255, 2), "vault_seal": (24, 2),
    "trig_overflow": (233, 2), "trig_shape": (142, 4),
    "trig_bounds": (37, 4), "halt": (76, 2),
}


@dataclass
class Function:
    name: str
    arity: int
    locals: int
    max_stack: int
    items: list[tuple] = field(default_factory=list)

    def emit(self, op: str, *args: object) -> "Function":
        self.items.append((op, *args))
        return self

    def mark(self, label: str) -> "Function":
        self.items.append(("@", label))
        return self


class Program:
    def __init__(self) -> None:
        self.constants: list[bytes] = []
        self.functions: list[Function] = []

    def string(self, value: str) -> int:
        self.constants.append(value.encode())
        return len(self.constants) - 1

    def function(self, name: str, arity: int, locals_: int,
                 max_stack: int) -> Function:
        fn = Function(name, arity, locals_, max_stack)
        self.functions.append(fn)
        return fn

    def assemble(self) -> bytes:
        ids = {fn.name: i for i, fn in enumerate(self.functions)}
        bodies: list[tuple[Function, bytes, int]] = []
        total = 0
        for fn in self.functions:
            labels: dict[str, int] = {}
            offset = 0
            for item in fn.items:
                if item[0] == "@":
                    labels[item[1]] = offset
                else:
                    offset += OPS[item[0]][1]
            code = bytearray()
            count = 0
            for item in fn.items:
                op, *args = item
                if op == "@":
                    continue
                raw, size = OPS[op]
                here = len(code)
                code.append(raw)
                if size == 2:
                    operand = int(args[0]) & 0xff if args else 0
                    code.append(operand)
                elif size == 8:
                    code.extend(struct.pack("<i", int(args[0])))
                    code.extend(b"\0\0\0")
                elif op in {"jump", "jump_zero", "try_begin"}:
                    relative = labels[str(args[0])] - (here + size)
                    code.extend(struct.pack("<hB", relative, 0))
                elif op == "call":
                    code.extend(bytes((ids[str(args[0])], int(args[1]), 0)))
                elif op == "trig_bounds":
                    code.extend(bytes((int(args[0]), int(args[1]), 0)))
                else:
                    code.extend(struct.pack("<HB", int(args[0]), 0))
                count += 1
            bodies.append((fn, bytes(code), count))
            total += count

        constants = bytearray()
        for data in self.constants:
            constants.extend(struct.pack("<BBH", 1, 0, len(data)))
            constants.extend(data)
            while len(constants) % 4:
                constants.append(0)
        const_off = 32
        funcs_off = const_off + len(constants)
        code_off = funcs_off + 16 * len(bodies)
        table, code = bytearray(), bytearray()
        for fn, body, count in bodies:
            table.extend(struct.pack("<BBBBIIHH", fn.arity, fn.locals,
                                     fn.max_stack, 0, len(code), len(body),
                                     count, 0))
            code.extend(body)
        file_size = code_off + len(code) + 32
        header = struct.pack("<4sHHHHIIIII", b"PPBC", 1, len(bodies),
                             len(self.constants), 0, total, const_off,
                             funcs_off, code_off, file_size)
        payload = header + constants + table + code
        return payload + hashlib.sha256(payload).digest()


def add_family(fn: Function, pad_count: int, try_depth: int,
               trigger: str, trigger_args: tuple[int, ...] = ()) -> None:
    for depth in range(try_depth):
        fn.emit("try_begin", f"handler_{depth}")
    for _ in range(pad_count):
        fn.emit("call", "pad", 0).emit("pop")
    fn.emit("cap_public").emit("call", "guard", 1).emit("pop")
    if trigger == "trig_overflow":
        fn.emit("push_i32", (1 << 31) - 1).emit("push_i8", 1)
    fn.emit(trigger, *trigger_args)
    if trigger == "trig_overflow":
        fn.emit("pop")
    for _ in range(try_depth):
        fn.emit("try_end")
    fn.emit("push_null").emit("ret")
    for depth in reversed(range(try_depth)):
        fn.mark(f"handler_{depth}").emit("catch").emit("pop")
        fn.emit("push_null").emit("ret")


def build(pads: tuple[int, int, int], slot: int) -> bytes:
    if not 1 <= slot < 14 or any(not 0 <= value <= 60 for value in pads):
        raise ValueError("parameter range")
    p = Program()
    message = p.string("archive:afterimage:open")
    main = p.function("main", 0, 16, 4)
    pad = p.function("pad", 0, 1, 1)
    guard = p.function("guard", 1, 14, 1)
    alpha = p.function("alpha", 0, 2, 4)
    beta = p.function("beta", 0, 2, 3)
    gamma = p.function("gamma", 0, 2, 3)
    pad.emit("push_null").emit("ret")
    guard.emit("load", 0).emit("store", slot).emit("load", slot)
    guard.emit("cap_check").emit("ret")
    add_family(alpha, pads[0], 2, "trig_overflow")
    add_family(beta, pads[1], 3, "trig_shape", (2,))
    add_family(gamma, pads[2], 4, "trig_bounds", (2, 5))

    loop_class = 1
    main.emit("cap_public").emit("store", slot)
    main.emit("push_i8", 0).emit("store", 0).mark("outer")
    main.emit("loop_hint", loop_class).emit("load", 0).emit("push_i8", 1)
    main.emit("add").emit("store", 0).emit("osr", loop_class)
    main.emit("call", "alpha", 0).emit("pop")
    main.emit("call", "beta", 0).emit("pop")
    main.emit("call", "gamma", 0).emit("pop")
    main.emit("load", 0).emit("push_i8", 6).emit("lt")
    main.emit("jump_zero", "done").emit("jump", "outer")
    main.mark("done").emit("deopt_hint").emit("load", slot)
    main.emit("push_const", message).emit("vault_seal").emit("pop")
    main.emit("halt")
    return p.assemble()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pads", default="0,0,0",
                        help="alpha,beta,gamma padding call counts")
    parser.add_argument("--slot", type=int, default=1,
                        help="shared user/guard local slot (1..13)")
    args = parser.parse_args()
    pads = tuple(map(int, args.pads.split(",")))
    if len(pads) != 3:
        raise SystemExit("--pads needs three comma-separated integers")
    data = build(pads, args.slot)
    with open("candidate.pbc", "wb") as output:
        output.write(data)
    print(f"candidate.pbc written ({len(data)} bytes), pads={pads}, slot={args.slot}")


if __name__ == "__main__":
    main()
