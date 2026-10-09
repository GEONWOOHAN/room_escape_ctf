from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROGRAM_SRC = ROOT / "author" / "program_src"
sys.path.insert(0, str(PROGRAM_SRC))

from assembler import Assembler  # noqa: E402
from isa import MEM_SIZE  # noqa: E402
from vm_model import VM  # noqa: E402


def memory_with_qword(addr: int, value: int) -> bytes:
    memory = bytearray(MEM_SIZE)
    memory[addr:addr + 8] = struct.pack("<Q", value)
    return bytes(memory)


class CacheSemanticsTests(unittest.TestCase):
    def test_dirty_fault_discards_without_writeback(self) -> None:
        asm = Assembler()
        asm.movi(0, 0x2222)
        store_checkpoint = asm.store(0, 0)
        asm.load(1, 0)
        asm.halt(64)
        vm = VM(memory_with_qword(0, 0x1111), asm.instructions)
        vm.run([(store_checkpoint, 0)])
        self.assertEqual(vm.regs[1], 0x1111)
        self.assertEqual(int.from_bytes(vm.dram[:8], "little"), 0x1111)

    def test_flush_makes_later_fault_a_noop(self) -> None:
        asm = Assembler()
        asm.movi(0, 0x2222)
        asm.store(0, 0)
        flush_checkpoint = asm.flush(0)
        asm.load(1, 0)
        asm.halt(64)
        vm = VM(memory_with_qword(0, 0x1111), asm.instructions)
        vm.run([(flush_checkpoint, 0)])
        self.assertEqual(vm.regs[1], 0x2222)
        self.assertEqual(int.from_bytes(vm.dram[:8], "little"), 0x2222)

    def test_eviction_writes_back_dirty_line(self) -> None:
        asm = Assembler()
        asm.movi(0, 0xA5A5)
        asm.store(0, 0)
        for line in range(1, 34):
            asm.load(1, line * 64)
        asm.halt(63 * 64)
        vm = VM(bytes(MEM_SIZE), asm.instructions)
        vm.run()
        self.assertEqual(int.from_bytes(vm.dram[:8], "little"), 0xA5A5)

    def test_replay_is_deterministic(self) -> None:
        asm = Assembler()
        asm.movi(0, 7)
        asm.store(0, 0)
        asm.halt(64)
        first = VM(bytes(MEM_SIZE), asm.instructions).run()
        second = VM(bytes(MEM_SIZE), asm.instructions).run()
        self.assertEqual(first["digest"], second["digest"])


if __name__ == "__main__":
    unittest.main()

