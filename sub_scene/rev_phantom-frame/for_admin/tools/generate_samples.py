#!/usr/bin/env python3

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ADMIN = HERE.parent
USER = ADMIN.parent / "for_user"
sys.path.insert(0, str(HERE))

from pbc import Program, safe_program  # noqa: E402
from recover_map import recover_opcode_map  # noqa: E402


def osr_demo() -> Program:
    p = Program("main")
    f = p.function("main", arity=0, locals=1, max_stack=2)
    f.emit("push_i8", 0).emit("store", 0).mark("loop")
    f.emit("loop_hint", 0x44).emit("load", 0).emit("push_i8", 1)
    f.emit("add").emit("store", 0).emit("osr", 0x44)
    f.emit("load", 0).emit("push_i8", 4).emit("lt")
    f.emit("jump_zero", "done").emit("jump", "loop")
    f.mark("done").emit("halt")
    return p


def exception_demo() -> Program:
    p = Program("main")
    f = p.function("main", arity=0, locals=1, max_stack=2)
    f.emit("try_begin", "handler").emit("push_i8", 7).emit("throw")
    f.emit("try_end").emit("halt")
    f.mark("handler").emit("catch").emit("pop").emit("halt")
    return p


def main() -> None:
    samples = USER / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    opcode_map = recover_opcode_map(USER / "phantom_vm")
    safe = safe_program().assemble(opcode_map)
    (samples / "safe.pbc").write_bytes(safe)
    (samples / "osr_demo.pbc").write_bytes(osr_demo().assemble(opcode_map))
    (samples / "exception_demo.pbc").write_bytes(
        exception_demo().assemble(opcode_map)
    )
    (USER / "candidate.pbc").write_bytes(safe)
    print("samples and starter candidate generated")


if __name__ == "__main__":
    main()
