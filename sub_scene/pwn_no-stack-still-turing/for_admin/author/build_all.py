#!/usr/bin/env python3
import argparse
import hashlib
import json
import random
import shutil
import struct
import subprocess
from itertools import product
from pathlib import Path

import config
from crypto import seal
from mips import emit_op, emit_route, jr
from mips import r as r_ins
from mips import sw
from vm_runtime import challenge_aad, execute, rol32
from elf import build_elf


DIST = config.ROOT / ".build" / "for_user"


def publish_handout():
    """Copy a completed admin build into the public handout directory."""
    if not DIST.is_dir():
        raise RuntimeError("admin handout build is missing")
    target = config.PUBLIC_DIST
    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise RuntimeError(f"refusing to replace non-directory release path: {target}")
        shutil.rmtree(target)
    shutil.copytree(DIST, target)


def op(kind, d, s, rot, arg_index, byte_index=0):
    return (kind, d, s, rot, arg_index, byte_index)


def make_goal(rng):
    kinds = ["arx"] * (config.CHAIN_LENGTH * 2)
    for index in (5, 31, 47):
        kinds[index] = "zext16"
    for index in (14, 38, 52):
        kinds[index] = "sext16"
    for index in (23, 35, 49, 55):
        kinds[index] = "partial"
    goal = []
    ki = 0
    for step in range(config.CHAIN_LENGTH):
        phase = step // 4
        base = step % 4
        distance = (1, 2, 4, 3, 5, 6, 7)[phase]
        d0, d1 = base, base + 4
        a = op(kinds[ki], d0, (d0 + distance) & 7,
               (5 + step * 3) % 31 + 1, 0, (step + 1) & 3); ki += 1
        b = op(kinds[ki], d1, (d1 + distance) & 7,
               (11 + step * 5) % 31 + 1, 1, (step + 2) & 3); ki += 1
        goal.append((a, b))
    return goal


def make_decoy(rng):
    choices = ["arx", "zext16", "sext16", "partial", "partial16"]
    def one(arg_index):
        kind = rng.choice(choices)
        return op(kind, rng.randrange(8), rng.randrange(8), rng.randrange(1, 32),
                  arg_index, rng.randrange(4))
    return one(0), one(1)


def encode_function(desc, route, fn_id, trap=False):
    words = []
    for index, item in enumerate(desc):
        kind = item[0]
        mapped = "byte" if kind == "partial" else "half" if kind == "partial16" else kind
        variant = int.from_bytes(
            hashlib.sha256(
                struct.pack("<QI", config.INSTANCE_SEED, fn_id)
                + bytes([index])
                + repr(item).encode()
            ).digest()[:8],
            "little",
        )
        chunk = emit_op(
            mapped,
            *item[1:],
            delay_trap=(trap and index == 0),
            variant=variant,
        )
        words += chunk
    words += emit_route(*route, variant=fn_id)
    return_register = 2 + (fn_id % 14)
    if return_register == 4:
        return_register = 17
    words += [jr(31), r_ins(return_register, return_register, return_register, 0, 0x26)]
    return b"".join(struct.pack("<I", x) for x in words)


def eval_one(state, item, constants):
    kind, d, s, rot, arg_index, byte_index = item
    source = state[s]
    if kind == "zext16":
        source &= 0xffff
    elif kind == "sext16":
        source &= 0xffff
        if source & 0x8000: source |= 0xffff0000
    value = ((state[d] ^ source) + constants[arg_index]) & 0xffffffff
    value = ((value >> rot) | (value << (32 - rot))) & 0xffffffff
    if kind == "partial":
        mask = 0xff << (byte_index * 8)
        state[d] = (state[d] & ~mask) | ((value & 0xff) << (byte_index * 8))
    elif kind == "partial16":
        state[d] = (state[d] & 0xffff0000) | (value & 0xffff)
    else:
        state[d] = value


def eval_goal(inputs, goal, constants):
    state = list(inputs)
    for desc, consts in zip(goal, constants):
        eval_one(state, desc[0], consts)
        eval_one(state, desc[1], consts)
    return state


def rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & 0xffffffff


def route_forward(state, route):
    first, second = state
    term0, term1, rotation0, rotation1 = route
    first = (rotate_right(first ^ term0, rotation0) + second) & 0xffffffff
    second = (rotate_right(second ^ term1, rotation1) + first) & 0xffffffff
    return first, second


def payload(records):
    out = bytearray(b"NSST" + struct.pack("<HHII", 3, config.PATCH_RECORD_COUNT, config.START_TOKEN, 0))
    for typ, off, addr, value in records:
        out += struct.pack("<BBHII", typ, 0, off, addr, value)
    return bytes(out)


def main():
    rng = random.Random(config.INSTANCE_SEED)
    if DIST.exists():
        for child in DIST.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    DIST.mkdir(parents=True, exist_ok=True)
    config.PRIVATE.mkdir(parents=True, exist_ok=True)
    config.SOLUTION.mkdir(parents=True, exist_ok=True)
    print("[1/6] 목표 연산과 가젯 카탈로그 생성")
    goal = make_goal(rng)
    alias_id_pool = rng.sample(
        range(config.GADGET_COUNT), config.CHAIN_LENGTH * config.ALIAS_COUNT
    )
    alias_groups = [
        alias_id_pool[index * config.ALIAS_COUNT:(index + 1) * config.ALIAS_COUNT]
        for index in range(config.CHAIN_LENGTH)
    ]
    intended_ids = [rng.choice(group) for group in alias_groups]
    catalog = [None] * config.GADGET_COUNT
    used = {repr(x) for x in goal}
    semantic_steps = [None] * config.GADGET_COUNT
    for step, (group, desc) in enumerate(zip(alias_groups, goal)):
        for fn_id in group:
            catalog[fn_id] = desc
            semantic_steps[fn_id] = step
    for fn_id in range(config.GADGET_COUNT):
        if catalog[fn_id] is not None: continue
        while True:
            desc = make_decoy(rng)
            key = repr(desc)
            if key not in used:
                used.add(key); catalog[fn_id] = desc; break

    route_models = [
        (rng.getrandbits(32), rng.getrandbits(32), rng.randrange(3, 30), rng.randrange(3, 30))
        for _ in range(config.GADGET_COUNT)
    ]
    route_target = (0, 0)
    for fn_id in intended_ids:
        route_target = route_forward(route_target, route_models[fn_id])

    print("[2/6] MIPS32 ELF 생성")
    encoded_functions = {
        fn_id: encode_function(desc, route_models[fn_id], fn_id, trap=(fn_id == intended_ids[9]))
        for fn_id, desc in enumerate(catalog)
    }
    physical_order = list(range(config.GADGET_COUNT))
    rng.shuffle(physical_order)
    text = bytearray()
    function_addresses = [0] * config.GADGET_COUNT
    for fn_id in physical_order:
        gap = rng.randrange(0x10, 0x91)
        offset = (len(text) + gap + 3) & ~3
        text.extend(bytes(offset - len(text)))
        function_addresses[fn_id] = config.TEXT_BASE + offset
        text.extend(encoded_functions[fn_id])
    inputs = [rng.getrandbits(32) for _ in range(8)]
    inputs[2] = (inputs[2] & 0xffff0000) | 0x8f31
    ro = bytearray(0x1000)
    struct.pack_into("<8I", ro, config.INPUT_ADDR - config.RO_BASE, *inputs)
    for n in range(config.GADGET_COUNT):
        struct.pack_into("<I", ro, config.FN_TABLE_ADDR - config.RO_BASE + n * 4,
                         function_addresses[n])
    target = build_elf(bytes(text), bytes(ro), config.TEXT_BASE, config.RO_BASE)
    (DIST / "target.elf").write_bytes(target)

    print("[3/6] 힙 이미지와 제한 쓰기 퍼즐 생성")
    image = bytearray(0x10040)
    struct.pack_into("<I", image, config.ARG_BIAS_ADDR - config.HEAP_BASE, 0x40)
    struct.pack_into("<II", image, config.ROUTE_TARGET_ADDR - config.HEAP_BASE, *route_target)
    constants = []
    node_offsets = rng.sample(list(range(0x100, 0x1000, 0x10)), config.CHAIN_LENGTH)
    wrong_steps = sorted(rng.sample(range(2, config.CHAIN_LENGTH - 2), config.HEAP_WRITE_COUNT // 2))
    wrong_ids = {}
    for step in range(config.CHAIN_LENGTH):
        node_off = node_offsets[step]
        arg_off = config.ARG_BASE_OFF + step * 0x10
        next_off = node_offsets[step + 1] if step + 1 < config.CHAIN_LENGTH else 0xffffffff
        fn_id = intended_ids[step]
        if step in wrong_steps:
            candidates = [n for n in range(config.GADGET_COUNT) if semantic_steps[n] is None]
            fn_id = candidates[(step * 17) % len(candidates)]
            wrong_ids[step] = fn_id
        guard = rol32(fn_id ^ arg_off ^ next_off ^ config.COOKIE, 7)
        struct.pack_into("<4I", image, node_off, fn_id, arg_off, next_off, guard)
        c = (rng.getrandbits(32), rng.getrandbits(32)); constants.append(c)
        struct.pack_into("<2I", image, arg_off, *c)
    decoy_off = next(
        offset for offset in range(0x100, 0x1000, 0x10) if offset not in set(node_offsets)
    )
    decoy_fn, decoy_arg, decoy_next = 0, config.ARG_BASE_OFF, 0xffffffff
    decoy_guard = rol32(decoy_fn ^ decoy_arg ^ decoy_next ^ config.COOKIE, 7)
    struct.pack_into("<4I", image, decoy_off, decoy_fn, decoy_arg, decoy_next, decoy_guard)
    struct.pack_into("<I", image, config.START_PTR_ADDR - config.HEAP_BASE, decoy_off)
    (DIST / "memory.img").write_bytes(image)

    uncertain_groups = [alias_groups[step] for step in wrong_steps]
    matching_routes = 0
    for replacements in product(*uncertain_groups):
        selected = dict(zip(wrong_steps, replacements))
        state = (0, 0)
        for step, intended in enumerate(intended_ids):
            state = route_forward(state, route_models[selected.get(step, intended)])
        if state == route_target:
            matching_routes += 1
            if matching_routes > 1:
                break
    if matching_routes != 1:
        raise RuntimeError(f"route alias solution count is {matching_routes}")

    solution_records = [
        (1, 0, config.START_PTR_ADDR, node_offsets[0]),
        (1, 0, config.ARG_BIAS_ADDR, 0),
    ]
    for step in wrong_steps:
        node_off = node_offsets[step]
        arg_off = config.ARG_BASE_OFF + step * 0x10
        next_off = node_offsets[step + 1] if step + 1 < config.CHAIN_LENGTH else 0xffffffff
        fn_id = intended_ids[step]
        guard = rol32(fn_id ^ arg_off ^ next_off ^ config.COOKIE, 7)
        solution_records += [(2, node_off, 0, fn_id), (2, node_off + 12, 0, guard)]
    solution_payload = payload(solution_records)
    (config.SOLUTION / "solution_payload.bin").write_bytes(solution_payload)

    template_records = [
        (1, 0, config.START_PTR_ADDR, decoy_off),
        (1, 0, config.ARG_BIAS_ADDR, 0x40),
    ]
    for n in range(config.HEAP_WRITE_COUNT):
        off = config.ARG_BASE_OFF + n * 4
        template_records.append((2, off, 0, struct.unpack_from("<I", image, off)[0]))
    (DIST / "payload.template.bin").write_bytes(payload(template_records))

    vectors = [inputs]
    vectors.extend([
        [0x10203040 ^ (n * 0x11111111) ^ vector * 0x01010101 for n in range(8)]
        for vector in range(1, 5)
    ])
    vectors.append([0x80008000, 0x7fff0001, 0xffff8f31, 0x00007fff, 0xdeadbeef, 0, 1, 0xffffffff])
    vectors.append([0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10203040, 0x50607080, 0x90a0b0c0, 0xd0e0f000])
    vectors.append([rng.getrandbits(32) for _ in range(8)])
    if len(vectors) != config.VECTOR_COUNT:
        raise RuntimeError("vector count drifted")
    vector_blob = b"NSV3" + struct.pack("<HH", config.VECTOR_COUNT, 8)
    vector_blob += b"".join(struct.pack("<8I", *vector) for vector in vectors)
    (DIST / "vectors.bin").write_bytes(vector_blob)

    print("[4/6] 목표 문서와 실행기 배치")
    lines = [
        "space RAM 32 little",
        f"input W[0..7] = load32(0x{config.INPUT_ADDR:08x} + 4*n)",
        "semantics: operations inside each STEP execute from left to right",
        "arx(d,s,r,c): W[d] = ror32((W[d] xor W[s]) + c, r)",
        "zext16(d,s,r,c): W[d] = ror32((W[d] xor zext16(W[s][15:0])) + c, r)",
        "sext16(d,s,r,c): W[d] = ror32((W[d] xor sext16(W[s][15:0])) + c, r)",
        "partial(d,s,r,c,b): store8(byte_address(W[d])+b, low8(ror32((W[d] xor W[s])+c,r)))",
        f"each function also updates hidden route words at 0x{config.ROUTE_STATE0_ADDR:08x}/0x{config.ROUTE_STATE1_ADDR:08x}",
        "route transition must be recovered from target.elf; visible W semantics alone are not a function identity",
        f"required terminal route target is stored at 0x{config.ROUTE_TARGET_ADDR:08x}",
        "",
    ]
    for step, (desc, consts) in enumerate(zip(goal, constants)):
        rendered = []
        for item in desc:
            kind, d, s, rot, arg_idx, byte_idx = item
            c = consts[arg_idx]
            extra = f",{byte_idx}" if kind == "partial" else ""
            rendered.append(f"{kind}({d},{s},{rot},0x{c:08x}{extra})")
        lines.append(f"STEP {step:02d}: {rendered[0]} ; {rendered[1]}")
    lines += ["", f"store32(0x{config.RESULT_ADDR:08x} + 4*n, W[n]) for n in 0..7",
              f"store8(0x{config.RESULT_ADDR + 0x20:08x}, 1)"]
    (DIST / "goal.pcode").write_text("\n".join(lines) + "\n", encoding="utf-8")
    subprocess.run([
        "gcc", "-std=c11", "-O2", "-fPIE", "-pie", "-s",
        "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-Wno-deprecated-declarations",
        str(Path(__file__).with_name("native_checker.c")), "-lcrypto",
        "-o", str(DIST / "checker"),
    ], check=True)
    (DIST / "checker").chmod(0o755)

    print("[5/6] canonical 실행 receipt 키로 플래그 암호화")
    from vm_runtime import execute_fleet
    key, status = execute_fleet(target, bytes(image), solution_payload, vector_blob)
    if status != 1: raise RuntimeError("reference execution failed")
    nonce = hashlib.sha256(struct.pack("<Q", config.INSTANCE_SEED) + b"nonce").digest()[:12]
    aad = challenge_aad(target, bytes(image), vector_blob)
    ciphertext, tag = seal(key, nonce, aad, config.FLAG)
    enc = b"NSFE" + struct.pack("<HH", 4, 12) + nonce + struct.pack("<I", len(ciphertext)) + ciphertext + tag
    (DIST / "flag.enc").write_bytes(enc)

    private = {
        "intended_fn_ids": intended_ids,
        "alias_groups": alias_groups,
        "semantic_steps": semantic_steps,
        "route_models": route_models,
        "route_target": route_target,
        "wrong_steps": wrong_steps,
        "wrong_fn_ids": wrong_ids,
        "node_offsets": node_offsets,
        "function_addresses": function_addresses,
        "decoy_offset": decoy_off,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "target_sha256": hashlib.sha256(target).hexdigest(),
    }
    (config.SOLUTION / "solution.json").write_text(json.dumps(private, indent=2) + "\n")
    (config.SOLUTION / "gadget_catalog.json").write_text(json.dumps([
        {"semantic": desc, "semantic_step": semantic_steps[fn_id], "route": route_models[fn_id]}
        for fn_id, desc in enumerate(catalog)
    ], indent=2) + "\n")
    (config.PRIVATE / "flag.txt").write_bytes(config.FLAG + b"\n")
    print("[6/6] 빌드 완료")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build No Stack Still Turing inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after building, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    main()
    if arguments.publish:
        publish_handout()
