from __future__ import annotations

from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "author/vendor"))
from keystone import Ks, KS_ARCH_ARM, KS_MODE_THUMB

FLASH = 0x08000000
RESET = FLASH + 0x100
ISR = FLASH + 0x400
ERROR = FLASH + 0x500
TARGET_TABLE_SLOTS = tuple(FLASH + offset for offset in (0x1000, 0x1100, 0x1200))
NONCE_SLOTS = tuple(FLASH + offset for offset in (0x1300, 0x1320, 0x1340))
ROUTE_TARGET_SLOTS = tuple(FLASH + offset for offset in (0x1380, 0x1390, 0x13A0))
CALLBACK_POINTER_SLOTS = tuple(FLASH + offset for offset in (0x900, 0xB00, 0xD00))
CALLBACK_REGION = FLASH + 0x2000
FLASH_SIZE = 0x10000
SRAM = 0x20000000
STATE = SRAM + 0x200
PERMUTATION = SRAM + 0x300
CALLBACK_TABLE = SRAM + 0x400
CALIBRATION = SRAM + 0x1000
CONTEXT = SRAM + 0x2000
MMIO = 0x40001000
NVIC = 0xE000E100
STACK = SRAM + 0xF000

CALLBACK_COUNT = 96
CHAIN_LENGTH = 20
CHOICES_PER_LAYER = 4
OUTPUT_OFFSET = 24
ROUTE_STATE0_OFFSET = OUTPUT_OFFSET + CHAIN_LENGTH * 8
ROUTE_STATE1_OFFSET = ROUTE_STATE0_OFFSET + 4


def load(register: str, value: int) -> str:
    return f"movw {register}, #{value & 0xffff}; movt {register}, #{value >> 16}"


def rotate_left(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def materialize(
    register: str,
    value: int,
    family: int,
    rng: random.Random,
    scratch: str = "r12",
) -> str:
    """Emit one of several equivalent constant-construction dataflows."""
    value &= 0xFFFFFFFF
    if family == 0:
        mask = rng.getrandbits(32) or 1
        return (
            f"{load(register, value ^ mask)}; "
            f"{load(scratch, mask)}; "
            f"eor {register}, {register}, {scratch}"
        )
    if family == 1:
        addend = rng.getrandbits(32) or 1
        return (
            f"{load(register, (value - addend) & 0xFFFFFFFF)}; "
            f"{load(scratch, addend)}; "
            f"add {register}, {register}, {scratch}"
        )
    if family == 2:
        subtrahend = rng.getrandbits(32) or 1
        return (
            f"{load(register, (value + subtrahend) & 0xFFFFFFFF)}; "
            f"{load(scratch, subtrahend)}; "
            f"sub {register}, {register}, {scratch}"
        )
    if family == 3:
        rotation = rng.randrange(3, 30)
        return f"{load(register, rotate_left(value, rotation))}; ror {register}, {register}, #{rotation}"
    if family == 4:
        return f"{load(register, (~value) & 0xFFFFFFFF)}; mvn {register}, {register}"
    if family == 5:
        rotation = rng.randrange(3, 30)
        mask = rng.getrandbits(32) or 1
        encoded = rotate_left(value ^ mask, rotation)
        return (
            f"{load(register, encoded)}; ror {register}, {register}, #{rotation}; "
            f"{load(scratch, mask)}; eor {register}, {register}, {scratch}"
        )
    raise ValueError("unknown callback codegen family")


def assemble(text: str, address: int) -> bytes:
    engine = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    encoded, _ = engine.asm(text, addr=address)
    return bytes(encoded)


def callback_source(
    expected: int,
    following: int,
    constants: list[int],
    shifts: list[int],
    route_terms: tuple[int, int],
    route_rotations: tuple[int, int],
    terminal_guard: int,
    route_target_address: int,
    codegen_family: int,
    rng: random.Random,
) -> str:
    terminal_check = ""
    if following == terminal_guard:
        terminal_check = f"""
        {load('r12', route_target_address)}
        ldr r12, [r12]
        cmp r5, r12
        bne callback_bad_terminal
        {load('r12', route_target_address + 4)}
        ldr r12, [r12]
        cmp r6, r12
        beq callback_emit
    callback_bad_terminal:
        {load('r12', 0xA55A3CC3)}
        eor r0, r0, r12
        eor r1, r1, r12
        eor r2, r2, r12
        eor r3, r3, r12
        """
    return f"""
        push {{r4-r7, lr}}
        {load('r4', CONTEXT)}
        ldr r5, [r4, #0]
        {materialize('r6', expected, codegen_family, rng)}
        cmp r5, r6
        bne callback_fail
        ldr r0, [r4, #8]
        ldr r1, [r4, #12]
        ldr r2, [r4, #16]
        ldr r3, [r4, #20]
        {materialize('r5', constants[0], codegen_family, rng)}
        eor r0, r0, r5
        add r0, r0, r1
        ror r0, r0, #{shifts[0]}
        {materialize('r5', constants[1], codegen_family, rng)}
        eor r1, r1, r5
        add r1, r1, r2
        ror r1, r1, #{shifts[1]}
        {materialize('r5', constants[2], codegen_family, rng)}
        eor r2, r2, r5
        add r2, r2, r3
        ror r2, r2, #{shifts[2]}
        {materialize('r5', constants[3], codegen_family, rng)}
        eor r3, r3, r5
        add r3, r3, r0
        ror r3, r3, #{shifts[3]}
        ldr r5, [r4, #{ROUTE_STATE0_OFFSET}]
        ldr r6, [r4, #{ROUTE_STATE1_OFFSET}]
        {materialize('r7', route_terms[0], codegen_family, rng)}
        eor r5, r5, r7
        ror r5, r5, #{route_rotations[0]}
        add r5, r5, r6
        {materialize('r7', route_terms[1], codegen_family, rng)}
        eor r6, r6, r7
        ror r6, r6, #{route_rotations[1]}
        add r6, r6, r5
        str r5, [r4, #{ROUTE_STATE0_OFFSET}]
        str r6, [r4, #{ROUTE_STATE1_OFFSET}]
        {materialize('r7', following, codegen_family, rng)}
        {terminal_check}
        b callback_emit
    callback_fail:
        ldr r0, [r4, #8]
        ldr r1, [r4, #12]
        ldr r2, [r4, #16]
        ldr r3, [r4, #20]
        {materialize('r5', 0xDEADC0DE, codegen_family, rng)}
        eor r0, r0, r5
        eor r1, r1, r5
        eor r2, r2, r5
        eor r3, r3, r5
        {materialize('r7', following ^ 0xBAD0BAD0, codegen_family, rng)}
    callback_emit:
        ldr r5, [r4, #4]
        add r6, r4, #{OUTPUT_OFFSET}
        add r6, r6, r5
        str r0, [r6, #0]
        str r1, [r6, #4]
        add r5, r5, #8
        str r5, [r4, #4]
        str r0, [r4, #8]
        str r1, [r4, #12]
        str r2, [r4, #16]
        str r3, [r4, #20]
        str r7, [r4, #0]
        pop {{r4-r7, pc}}
    """


def rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def route_forward(
    state: tuple[int, int], terms: tuple[int, int], rotations: tuple[int, int]
) -> tuple[int, int]:
    first, second = state
    first = (rotate_right(first ^ terms[0], rotations[0]) + second) & 0xFFFFFFFF
    second = (rotate_right(second ^ terms[1], rotations[1]) + first) & 0xFFFFFFFF
    return first, second


def route_inverse(
    state: tuple[int, int], terms: tuple[int, int], rotations: tuple[int, int]
) -> tuple[int, int]:
    first, second = state
    old_second = rotate_left((second - first) & 0xFFFFFFFF, rotations[1]) ^ terms[1]
    old_first = rotate_left((first - old_second) & 0xFFFFFFFF, rotations[0]) ^ terms[0]
    return old_first, old_second


def build(
    seed: int = 0x47484F53,
    *,
    expected_nonce: bytes | None = None,
    real_choices: list[int] | None = None,
) -> tuple[bytes, dict[str, object]]:
    rng = random.Random(seed)
    image = bytearray(b"\xff" * FLASH_SIZE)
    if expected_nonce is None:
        expected_nonce = bytes(rng.randrange(256) for _ in range(16))
    if real_choices is None:
        real_choices = [rng.randrange(CHOICES_PER_LAYER) for _ in range(CHAIN_LENGTH)]
    if len(expected_nonce) != 16 or len(real_choices) != CHAIN_LENGTH:
        raise ValueError("invalid common fleet parameters")

    initial_guard = rng.getrandbits(32)
    guards = [initial_guard]
    while len(guards) < CHAIN_LENGTH + 1:
        value = rng.getrandbits(32)
        if value not in guards:
            guards.append(value)
    terminal_guard = guards[-1]

    target_table_address = rng.choice(TARGET_TABLE_SLOTS)
    nonce_address = rng.choice(NONCE_SLOTS)
    route_target_address = rng.choice(ROUTE_TARGET_SLOTS)
    # The fleet build seeds deliberately select different live slots; the two
    # remaining tables are still structurally valid decoys.
    callback_pointer_address = CALLBACK_POINTER_SLOTS[seed % len(CALLBACK_POINTER_SLOTS)]

    callback_ids = list(range(CALLBACK_COUNT))
    rng.shuffle(callback_ids)
    layer_ids = [
        callback_ids[layer * CHOICES_PER_LAYER:(layer + 1) * CHOICES_PER_LAYER]
        for layer in range(CHAIN_LENGTH)
    ]
    real_chain = [layer_ids[layer][real_choices[layer]] for layer in range(CHAIN_LENGTH)]
    graph: dict[int, tuple[int, int]] = {}
    for layer, choices in enumerate(layer_ids):
        for callback_id in choices:
            graph[callback_id] = (guards[layer], guards[layer + 1])
    used_guards = set(guards)
    for callback_id in callback_ids[CHAIN_LENGTH * CHOICES_PER_LAYER:]:
        expected = rng.getrandbits(32)
        following = rng.getrandbits(32)
        while expected in used_guards or following in used_guards or expected == following:
            expected = rng.getrandbits(32)
            following = rng.getrandbits(32)
        used_guards.update((expected, following))
        graph[callback_id] = (expected, following)

    route_terms = {
        callback_id: (rng.getrandbits(32), rng.getrandbits(32))
        for callback_id in range(CALLBACK_COUNT)
    }
    route_rotations = {
        callback_id: (rng.randrange(3, 30), rng.randrange(3, 30))
        for callback_id in range(CALLBACK_COUNT)
    }
    route_target = (0, 0)
    for callback_id in real_chain:
        route_target = route_forward(
            route_target, route_terms[callback_id], route_rotations[callback_id]
        )

    initial_regs = [rng.getrandbits(32) for _ in range(4)]
    targets = [rng.randrange(257) for _ in range(CALLBACK_COUNT)]
    reset_source = f"""
        {load('r0', CALIBRATION)}
        ldr r1, [r0, #4]
        cmp r1, #18
        bne idle
        {load('r2', nonce_address)}
        add r0, r0, #40
        movs r3, #4
    nonce_check:
        ldr r4, [r0], #4
        ldr r5, [r2], #4
        cmp r4, r5
        bne idle
        subs r3, r3, #1
        bne nonce_check
        {load('r4', CONTEXT)}
        {load('r5', initial_guard)}
        str r5, [r4, #0]
        movs r5, #0
        str r5, [r4, #4]
        str r5, [r4, #{ROUTE_STATE0_OFFSET}]
        str r5, [r4, #{ROUTE_STATE1_OFFSET}]
        {load('r5', initial_regs[0])}; str r5, [r4, #8]
        {load('r5', initial_regs[1])}; str r5, [r4, #12]
        {load('r5', initial_regs[2])}; str r5, [r4, #16]
        {load('r5', initial_regs[3])}; str r5, [r4, #20]
        {load('r0', CALLBACK_TABLE)}
        movs r1, #0
        str r1, [r0, #0]
        {load('r1', ERROR | 1)}
        str r1, [r0, #4]
        {load('r1', initial_guard)}
        str r1, [r0, #8]
        {load('r0', PERMUTATION)}
        movs r1, #0
    perm_init:
        strb r1, [r0, r1]
        adds r1, r1, #1
        cmp r1, #{CALLBACK_COUNT}
        bne perm_init
        {load('r2', CALIBRATION + 24)}
        ldr r4, [r2]
        cmp r4, #0
        bne seed_ok
        movs r4, #1
    seed_ok:
        movs r5, #{CALLBACK_COUNT - 1}
    shuffle_loop:
        eor r4, r4, r4, lsl #13
        eor r4, r4, r4, lsr #17
        eor r4, r4, r4, lsl #5
        and r6, r4, #255
        adds r1, r5, #1
    modulo_loop:
        cmp r6, r1
        blo modulo_done
        subs r6, r6, r1
        b modulo_loop
    modulo_done:
        ldrb r2, [r0, r5]
        ldrb r3, [r0, r6]
        strb r3, [r0, r5]
        strb r2, [r0, r6]
        subs r5, r5, #1
        bne shuffle_loop
        {load('r0', STATE)}
        movs r1, #0
        str r1, [r0, #0]
    main_loop:
        {load('r0', MMIO)}
        ldr r1, [r0, #0]
        tst r1, #1
        beq main_loop
        ldr r2, [r0, #4]
        ldr r3, [r0, #8]
        ldr r4, [r0, #16]
        add r4, r4, r2
        and r4, r4, #255
        str r4, [r0, #16]
        {load('r5', STATE)}
        str r3, [r5, #4]
        str r2, [r5, #8]
        str r4, [r5, #0]
        and r6, r3, #15
        {load('r5', CALIBRATION + 8)}
        ldrb r6, [r5, r6]
        eor r6, r6, r2
        add r6, r6, r4
        movw r5, #257
        cmp r6, r5
        blo reduced
        sub r6, r6, #257
    reduced:
        {load('r5', target_table_address)}
        ldrh r7, [r5, r3, lsl #1]
        cmp r6, r7
        bne main_loop
        {load('r0', NVIC)}
        movs r1, #1
        str r1, [r0]
        {load('r0', MMIO + 12)}
        str r1, [r0]
        svc #1
        {load('r0', CALLBACK_TABLE)}
        ldr r3, [r0, #4]
        blx r3
        b main_loop
    idle:
        wfi
        b idle
    """
    reset = assemble(reset_source, RESET)
    if len(reset) > ISR - RESET:
        raise RuntimeError("reset handler region overflow")
    image[RESET - FLASH:RESET - FLASH + len(reset)] = reset

    isr_source = f"""
        push {{r0-r4, lr}}
        {load('r0', STATE)}
        ldr r1, [r0, #4]
        {load('r2', PERMUTATION)}
        ldrb r1, [r2, r1]
        {load('r2', callback_pointer_address)}
        ldr r3, [r2, r1, lsl #2]
        adds r3, r3, #1
        {load('r2', CALLBACK_TABLE)}
        str r1, [r2, #0]
        str r3, [r2, #4]
        {load('r4', CONTEXT)}
        ldr r4, [r4, #0]
        str r4, [r2, #8]
        {load('r0', MMIO + 12)}
        movs r1, #0
        str r1, [r0]
        pop {{r0-r4, pc}}
    """
    isr = assemble(isr_source, ISR)
    image[ISR - FLASH:ISR - FLASH + len(isr)] = isr
    error_source = f"""
        {load('r0', CONTEXT)}
        ldr r1, [r0, #0]
        {load('r2', 0xBAD0BAD0)}
        eor r1, r1, r2
        str r1, [r0, #0]
        bx lr
    """
    error = assemble(error_source, ERROR)
    image[ERROR - FLASH:ERROR - FLASH + len(error)] = error

    callback_meta = []
    callback_addresses = [0] * CALLBACK_COUNT
    physical_order = list(range(CALLBACK_COUNT))
    rng.shuffle(physical_order)
    cursor = CALLBACK_REGION
    encoded_callbacks: dict[int, bytes] = {}
    for callback_id in physical_order:
        expected, following = graph[callback_id]
        constants = [rng.getrandbits(32) for _ in range(4)]
        shifts = [rng.randrange(3, 30) for _ in range(4)]
        cursor = (cursor + rng.randrange(0x10, 0x71) + 3) & ~3
        codegen_family = rng.randrange(6)
        source = callback_source(
            expected,
            following,
            constants,
            shifts,
            route_terms[callback_id],
            route_rotations[callback_id],
            terminal_guard,
            route_target_address,
            codegen_family,
            rng,
        )
        encoded = assemble(source, cursor)
        if cursor - FLASH + len(encoded) > FLASH_SIZE:
            raise RuntimeError("callback region overflow")
        callback_addresses[callback_id] = cursor
        encoded_callbacks[callback_id] = encoded
        offset = cursor - FLASH
        image[offset:offset + len(encoded)] = encoded
        callback_meta.append({
            "id": callback_id,
            "address": cursor,
            "expected": expected,
            "following": following,
            "size": len(encoded),
            "constants": constants,
            "shifts": shifts,
            "route_terms": route_terms[callback_id],
            "route_rotations": route_rotations[callback_id],
            "codegen_family": codegen_family,
        })
        cursor += len(encoded)

    image[0:8] = struct.pack("<II", STACK, RESET | 1)
    image[16 * 4:17 * 4] = struct.pack("<I", ISR | 1)
    for address in TARGET_TABLE_SLOTS:
        values = targets if address == target_table_address else [rng.randrange(257) for _ in range(CALLBACK_COUNT)]
        image[address - FLASH:address - FLASH + CALLBACK_COUNT * 2] = struct.pack(
            f"<{CALLBACK_COUNT}H", *values
        )
    for address in NONCE_SLOTS:
        value = expected_nonce if address == nonce_address else rng.randbytes(16)
        image[address - FLASH:address - FLASH + 16] = value
    for address in ROUTE_TARGET_SLOTS:
        value = route_target if address == route_target_address else (rng.getrandbits(32), rng.getrandbits(32))
        image[address - FLASH:address - FLASH + 8] = struct.pack("<II", *value)
    for address in CALLBACK_POINTER_SLOTS:
        values = list(callback_addresses)
        if address != callback_pointer_address:
            rng.shuffle(values)
        image[address - FLASH:address - FLASH + CALLBACK_COUNT * 4] = struct.pack(
            f"<{CALLBACK_COUNT}I", *values
        )
    metadata = {
        "seed": seed,
        "initial_guard": initial_guard,
        "terminal_guard": terminal_guard,
        "initial_regs": initial_regs,
        "expected_nonce": expected_nonce.hex(),
        "targets": targets,
        "route_target": route_target,
        "real_choices": real_choices,
        "real_chain": real_chain,
        "layers": layer_ids,
        "callbacks": sorted(callback_meta, key=lambda item: item["id"]),
        "addresses": {
            "flash": FLASH,
            "reset": RESET,
            "isr": ISR,
            "targets": target_table_address,
            "expected_nonce": nonce_address,
            "route_target": route_target_address,
            "callback_pointers": callback_pointer_address,
            "state": STATE,
            "permutation": PERMUTATION,
            "callback_table": CALLBACK_TABLE,
            "calibration": CALIBRATION,
            "context": CONTEXT,
            "mmio": MMIO,
            "nvic": NVIC,
            "stack": STACK,
        },
        "decoy_addresses": {
            "targets": [value for value in TARGET_TABLE_SLOTS if value != target_table_address],
            "expected_nonce": [value for value in NONCE_SLOTS if value != nonce_address],
            "route_target": [value for value in ROUTE_TARGET_SLOTS if value != route_target_address],
            "callback_pointers": [value for value in CALLBACK_POINTER_SLOTS if value != callback_pointer_address],
        },
    }
    return bytes(image), metadata
