import hashlib
import struct

TEXT_BASE = 0x00400000
RO_BASE = 0x00600000
INPUT_ADDR = RO_BASE + 0x120
FN_TABLE_ADDR = RO_BASE + 0x800
HEAP_BASE = 0x10000000
RESULT_ADDR = 0x10010000
ROUTE_STATE0_ADDR = RESULT_ADDR + 0x24
ROUTE_STATE1_ADDR = RESULT_ADDR + 0x28
START_PTR_ADDR = HEAP_BASE + 0x20
ARG_BIAS_ADDR = HEAP_BASE + 0x24
ROUTE_TARGET_ADDR = HEAP_BASE + 0x30
COOKIE = 0xC3D2E1F0
START_TOKEN = 0x91C4A72E
PROBLEM_ID = b"no-stack-still-turing-v4"
GADGET_COUNT = 360
CHAIN_LENGTH = 28
ABS_WRITE_COUNT = 2
HEAP_WRITE_COUNT = 12
PATCH_RECORD_COUNT = ABS_WRITE_COUNT + HEAP_WRITE_COUNT
VECTOR_COUNT = 8
RECEIPT_DOMAIN = b"no-stack-still-turing-receipt-v4\x00"


def challenge_aad(target_raw, image_raw, vectors_raw):
    return (
        PROBLEM_ID
        + hashlib.sha256(target_raw).digest()
        + hashlib.sha256(image_raw).digest()
        + hashlib.sha256(vectors_raw).digest()
    )


def rol32(v, n):
    n &= 31
    return ((v << n) | (v >> ((32 - n) & 31))) & 0xffffffff


class Memory:
    def __init__(self):
        self.regions = []

    def map(self, base, data, writable=False):
        self.regions.append((base, bytearray(data), writable))

    def _find(self, addr, size, write=False):
        for base, data, writable in self.regions:
            if base <= addr and addr + size <= base + len(data):
                if write and not writable:
                    raise RuntimeError("write to read-only memory")
                return data, addr - base
        raise RuntimeError("unmapped memory")

    def read(self, addr, size):
        data, off = self._find(addr, size)
        return bytes(data[off:off + size])

    def write(self, addr, value):
        data, off = self._find(addr, len(value), True)
        data[off:off + len(value)] = value

    def u8(self, addr): return self.read(addr, 1)[0]
    def u16(self, addr): return struct.unpack("<H", self.read(addr, 2))[0]
    def u32(self, addr): return struct.unpack("<I", self.read(addr, 4))[0]
    def w8(self, addr, v): self.write(addr, bytes([v & 0xff]))
    def w16(self, addr, v): self.write(addr, struct.pack("<H", v & 0xffff))
    def w32(self, addr, v): self.write(addr, struct.pack("<I", v & 0xffffffff))


def load_elf(mem, raw):
    if raw[:7] != b"\x7fELF\x01\x01\x01":
        raise RuntimeError("bad elf")
    phoff = struct.unpack_from("<I", raw, 28)[0]
    phentsize, phnum = struct.unpack_from("<HH", raw, 42)
    for n in range(phnum):
        p = struct.unpack_from("<IIIIIIII", raw, phoff + n * phentsize)
        typ, off, vaddr, _, filesz, memsz, flags, _ = p
        if typ == 1:
            mem.map(vaddr, raw[off:off + filesz] + b"\0" * (memsz - filesz), bool(flags & 2))


def run_function(mem, entry, state_addr, arg_addr, budget=200):
    regs = [0] * 32
    regs[4] = arg_addr; regs[16] = state_addr; regs[31] = 0xfffffff0
    pc = entry
    pending = None
    for _ in range(budget):
        ins = mem.u32(pc)
        next_pc = (pc + 4) & 0xffffffff
        op = ins >> 26; rs = (ins >> 21) & 31; rt = (ins >> 16) & 31
        rd = (ins >> 11) & 31; sa = (ins >> 6) & 31; fn = ins & 63
        imm = ins & 0xffff; simm = imm if imm < 0x8000 else imm - 0x10000
        branch = None
        if ins == 0:
            pass
        elif op == 0 and fn == 0x26:
            regs[rd] = regs[rs] ^ regs[rt]
        elif op == 0 and fn == 0x21:
            regs[rd] = (regs[rs] + regs[rt]) & 0xffffffff
        elif op == 0 and fn == 0x25:
            regs[rd] = regs[rs] | regs[rt]
        elif op == 0 and fn == 0x00:
            regs[rd] = (regs[rt] << sa) & 0xffffffff
        elif op == 0 and fn == 0x03:
            v = regs[rt]
            if v & 0x80000000: v -= 1 << 32
            regs[rd] = (v >> sa) & 0xffffffff
        elif op == 0 and fn == 0x02:
            v = regs[rt]
            if rs == 1:
                regs[rd] = ((v >> sa) | (v << (32 - sa))) & 0xffffffff
            else:
                regs[rd] = v >> sa
        elif op == 0 and fn == 0x08:
            branch = regs[rs]
        elif op == 0x23:
            regs[rt] = mem.u32((regs[rs] + simm) & 0xffffffff)
        elif op == 0x21:
            v = mem.u16((regs[rs] + simm) & 0xffffffff)
            regs[rt] = v | 0xffff0000 if v & 0x8000 else v
        elif op == 0x25:
            regs[rt] = mem.u16((regs[rs] + simm) & 0xffffffff)
        elif op == 0x2b:
            mem.w32((regs[rs] + simm) & 0xffffffff, regs[rt])
        elif op == 0x28:
            mem.w8((regs[rs] + simm) & 0xffffffff, regs[rt])
        elif op == 0x29:
            mem.w16((regs[rs] + simm) & 0xffffffff, regs[rt])
        elif op == 0x0c:
            regs[rt] = regs[rs] & imm
        elif op == 0x09:
            regs[rt] = (regs[rs] + simm) & 0xffffffff
        elif op == 0x0e:
            regs[rt] = regs[rs] ^ imm
        elif op == 0x04:
            if regs[rs] == regs[rt]:
                branch = (pc + 4 + (simm << 2)) & 0xffffffff
        else:
            raise RuntimeError("unsupported instruction")
        regs[0] = 0
        if pending is not None:
            pc = pending
            pending = None
            if pc == 0xfffffff0:
                return regs[2]
        else:
            pc = next_pc
            if branch is not None:
                pending = branch
    raise RuntimeError("function limit")


def parse_payload(raw):
    if len(raw) != 16 + PATCH_RECORD_COUNT * 12 or raw[:4] != b"NSST":
        raise ValueError("invalid payload")
    version, count, token, reserved = struct.unpack_from("<HHII", raw, 4)
    if version != 3 or count != PATCH_RECORD_COUNT or token != START_TOKEN or reserved:
        raise ValueError("invalid payload")
    records = []
    counts = {1: 0, 2: 0}; touched = set()
    for n in range(PATCH_RECORD_COUNT):
        typ, flags, off, addr, value = struct.unpack_from("<BBHII", raw, 16 + 12 * n)
        if typ not in counts or flags:
            raise ValueError("invalid payload")
        counts[typ] += 1
        if typ == 1:
            if off or addr not in (START_PTR_ADDR, ARG_BIAS_ADDR):
                raise PermissionError("write denied")
            target = addr
        else:
            if addr or off < 0x100 or off > 0xfffc or off >= 0xfffd:
                raise PermissionError("write denied")
            target = HEAP_BASE + off
        if target in touched or target & 3 or RESULT_ADDR <= target < RESULT_ADDR + 0x40:
            raise PermissionError("write denied")
        touched.add(target); records.append((target, value))
    if counts != {1: ABS_WRITE_COUNT, 2: HEAP_WRITE_COUNT}:
        raise ValueError("invalid payload")
    return records


def execute_detailed(target_raw, image_raw, payload_raw, input_words=None):
    mem = Memory(); load_elf(mem, target_raw)
    mem.map(HEAP_BASE, image_raw, True)
    for target, value in parse_payload(payload_raw):
        mem.w32(target, value)
    if input_words is None:
        input_words = [mem.u32(INPUT_ADDR + n * 4) for n in range(8)]
    if len(input_words) != 8:
        raise ValueError("exactly eight input words are required")
    for n, value in enumerate(input_words):
        mem.w32(RESULT_ADDR + n * 4, value)
    mem.w32(ROUTE_STATE0_ADDR, 0)
    mem.w32(ROUTE_STATE1_ADDR, 0)
    receipt = hashlib.sha256()
    receipt.update(RECEIPT_DOMAIN)
    receipt.update(mem.read(RESULT_ADDR, 32))
    off = mem.u32(START_PTR_ADDR)
    arg_bias = mem.u32(ARG_BIAS_ADDR)
    seen = 0
    while off != 0xffffffff:
        if off > 0xfff0 or off & 0xf:
            raise RuntimeError("bad node")
        node = HEAP_BASE + off
        fn_id, arg_off, next_off, guard = struct.unpack("<4I", mem.read(node, 16))
        if fn_id >= GADGET_COUNT or guard != rol32(fn_id ^ arg_off ^ next_off ^ COOKIE, 7):
            raise RuntimeError("bad guard")
        entry = mem.u32(FN_TABLE_ADDR + fn_id * 4)
        arg_addr = HEAP_BASE + ((arg_off + arg_bias) & 0xffff)
        before = mem.read(RESULT_ADDR, 32)
        route_before = mem.read(ROUTE_STATE0_ADDR, 8)
        run_function(mem, entry, RESULT_ADDR, arg_addr)
        after = mem.read(RESULT_ADDR, 32)
        route_after = mem.read(ROUTE_STATE0_ADDR, 8)
        receipt.update(struct.pack("<IIIII", seen, fn_id, arg_off, next_off, arg_addr - HEAP_BASE))
        receipt.update(before)
        receipt.update(after)
        receipt.update(route_before)
        receipt.update(route_after)
        off = next_off; seen += 1
        if seen > 64:
            raise TimeoutError("execution limit")
    if seen != CHAIN_LENGTH:
        raise RuntimeError("wrong chain length")
    route_state = (mem.u32(ROUTE_STATE0_ADDR), mem.u32(ROUTE_STATE1_ADDR))
    route_target = (mem.u32(ROUTE_TARGET_ADDR), mem.u32(ROUTE_TARGET_ADDR + 4))
    route_valid = route_state == route_target
    mem.w8(RESULT_ADDR + 0x20, int(route_valid))
    final_result = mem.read(RESULT_ADDR, 32)
    receipt.update(struct.pack("<I", seen))
    receipt.update(final_result)
    receipt.update(struct.pack("<II", *route_state))
    key = hashlib.sha256(RECEIPT_DOMAIN + receipt.digest()).digest()
    return key, int(route_valid), final_result


def execute(target_raw, image_raw, payload_raw):
    key, status, _final_result = execute_detailed(target_raw, image_raw, payload_raw)
    return key, status


def parse_vectors(raw):
    if len(raw) != 8 + VECTOR_COUNT * 32 or raw[:4] != b"NSV3":
        raise ValueError("invalid vectors")
    count, words = struct.unpack_from("<HH", raw, 4)
    if count != VECTOR_COUNT or words != 8:
        raise ValueError("invalid vectors")
    return [list(struct.unpack_from("<8I", raw, 8 + index * 32)) for index in range(count)]


def execute_fleet(target_raw, image_raw, payload_raw, vectors_raw):
    transcript = hashlib.sha256(b"no-stack-still-turing-vector-fleet-v4\x00")
    for vector_index, vector in enumerate(parse_vectors(vectors_raw)):
        key, status, result = execute_detailed(target_raw, image_raw, payload_raw, vector)
        if status != 1:
            return bytes(32), 0
        transcript.update(struct.pack("<I", vector_index))
        transcript.update(key)
        transcript.update(result)
    return hashlib.sha256(RECEIPT_DOMAIN + transcript.digest()).digest(), 1
