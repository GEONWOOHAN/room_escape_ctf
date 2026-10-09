#!/usr/bin/env python3
"""Generate the three-image Selective State Rewind v3 challenge."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve()
AUTHOR = HERE.parents[1]
ROOT = HERE.parents[2]
PROGRAM_SRC = AUTHOR / "program_src"
sys.path.insert(0, str(PROGRAM_SRC))

from assembler import Assembler  # noqa: E402
from isa import LINE_COUNT, LINE_SIZE, MEM_SIZE, canonical_plan, write_image, write_program  # noqa: E402
from vm_model import VM, hash_step  # noqa: E402

DEFAULT_SEED = 0x5E1EC71ECA5E2026
MASK64 = (1 << 64) - 1
AAD = b"selective-state-rewind-v3"
KDF_DOMAIN = b"selective-state-rewind-fleet-receipt-v3\x00"
IMAGE_NAMES = ("image_a", "image_b", "image_c")
FAULT_COUNT = 5
HANDOUT = ROOT / ".build" / "for_user"
PUBLIC_HANDOUT = ROOT.parent / "for_user"


def publish_handout() -> None:
    """Copy the completed admin-side build into the public handout directory."""
    if not HANDOUT.is_dir():
        raise RuntimeError("admin handout build is missing")
    if PUBLIC_HANDOUT.exists():
        if PUBLIC_HANDOUT.is_symlink() or not PUBLIC_HANDOUT.is_dir():
            raise RuntimeError(f"refusing to replace non-directory release path: {PUBLIC_HANDOUT}")
        shutil.rmtree(PUBLIC_HANDOUT)
    shutil.copytree(HANDOUT, PUBLIC_HANDOUT)


def derived_u64(label: str, index: int) -> int:
    digest = hashlib.sha256(f"{label}:{index}".encode()).digest()
    return int.from_bytes(digest[:8], "little")


IV = [derived_u64("audit-iv-v3", i) for i in range(4)]
HEAD_CONSTANTS = [derived_u64("audit-head-v3", i) for i in range(8)]
HEAD_ROTATIONS = [11, 23, 37, 51, 17, 29, 43, 7]
TAIL_CONSTANTS = [derived_u64("audit-tail-v3", i) for i in range(36)]
TAIL_ROTATIONS = [
    5, 13, 19, 31, 41, 47, 53, 59, 7, 17, 23, 37,
    43, 3, 11, 29, 49, 57, 9, 21, 33, 39, 51, 61,
    15, 27, 35, 45, 55, 1, 25, 33, 47, 57, 9, 19,
]


def compute_head(authenticated: int, uid: int) -> list[int]:
    state = IV.copy()
    for lane in range(4):
        state[lane] = hash_step(
            state[lane], authenticated, HEAD_CONSTANTS[2 * lane], HEAD_ROTATIONS[2 * lane]
        )
        state[lane] = hash_step(
            state[lane], uid, HEAD_CONSTANTS[2 * lane + 1], HEAD_ROTATIONS[2 * lane + 1]
        )
    return state


def put_u64(memory: bytearray, addr: int, value: int) -> None:
    memory[addr:addr + 8] = struct.pack("<Q", value & MASK64)


def line_addr(line: int, offset: int = 0) -> int:
    return line * LINE_SIZE + offset


def emit_store_immediate(asm: Assembler, reg: int, addr: int, value: int) -> None:
    asm.movi(reg, value)
    asm.store(reg, addr)


def emit_head(asm: Assembler, state_addr: int, auth_reg: int, uid_reg: int) -> None:
    for lane in range(4):
        asm.hashstep(
            state_addr + lane * 8,
            auth_reg,
            HEAD_CONSTANTS[2 * lane],
            HEAD_ROTATIONS[2 * lane],
        )
        asm.hashstep(
            state_addr + lane * 8,
            uid_reg,
            HEAD_CONSTANTS[2 * lane + 1],
            HEAD_ROTATIONS[2 * lane + 1],
        )


def emit_tail(asm: Assembler, state_addr: int, input_regs: list[int]) -> None:
    for index, (constant, rotation) in enumerate(zip(TAIL_CONSTANTS, TAIL_ROTATIONS)):
        asm.hashstep(
            state_addr + (index % 4) * 8,
            input_regs[index % len(input_regs)],
            constant,
            rotation,
        )


class ProgramGenerator:
    def __init__(
        self,
        rng: random.Random,
        decoy_lines: list[int],
        camouflage_addresses: list[int],
        variant: int,
    ):
        self.rng = rng
        self.decoy_lines = decoy_lines
        self.camouflage_addresses = camouflage_addresses
        self.variant = variant
        self.asm = Assembler()
        self.decoy_counter = 0
        self.camouflage_counter = 0

    def _registers(self, allowed: tuple[int, ...]) -> tuple[int, int, int]:
        if len(allowed) < 3:
            raise ValueError("camouflage needs three scratch registers")
        # Reproduce the old r0/r1 local signature frequently enough that it is
        # actively misleading rather than merely absent from the real sites.
        if self.camouflage_counter % 8 == 0 and {0, 1, 2}.issubset(allowed):
            return 2, 0, 1
        return tuple(self.rng.sample(list(allowed), 3))

    def _emit_camouflage(self, allowed: tuple[int, ...]) -> None:
        save, write_or_input, observed = self._registers(allowed)
        destination = self.camouflage_addresses[
            (self.camouflage_counter * 7 + self.variant * 5) % len(self.camouflage_addresses)
        ]
        self.asm.load(save, destination)
        if self.camouflage_counter & 1:
            source_line = self.decoy_lines[
                (self.camouflage_counter * 13 + self.variant) % len(self.decoy_lines)
            ]
            source = line_addr(source_line, (self.camouflage_counter % 8) * 8)
            self.asm.memcpy(destination, source, 8)
            self.asm.hashstep(
                destination,
                write_or_input,
                derived_u64(f"camouflage-hash-{self.variant}", self.camouflage_counter),
                (self.camouflage_counter * 9 + 7) % 63 + 1,
            )
            self.asm.load(observed, destination)
            self.asm.xor(observed, observed)
        else:
            value = derived_u64(
                f"camouflage-write-{self.variant}", self.camouflage_counter
            )
            self.asm.movi(write_or_input, value)
            self.asm.store(write_or_input, destination)
            self.asm.load(observed, destination)
            self.asm.xor(observed, write_or_input)
        # observed is zero at runtime, but the deliberately conservative
        # backward slicer must retain the whole apparent dependency chain.
        self.asm.xor(save, observed)
        self.asm.store(save, destination)
        self.camouflage_counter += 1

    def _emit_decoy(self, allowed: tuple[int, ...]) -> None:
        write, observed = self.rng.sample(list(allowed), 2)
        line = self.decoy_lines[(self.decoy_counter * (3 + self.variant)) % len(self.decoy_lines)]
        offset = ((self.decoy_counter * 11 + self.variant * 3) % 8) * 8
        addr = line_addr(line, offset)
        value = (
            (0, 1, 7, 8, 1000)[self.decoy_counter % 5]
            if self.decoy_counter % 4 == 0
            else derived_u64(f"decoy-write-{self.variant}", self.decoy_counter)
        )
        self.asm.movi(write, value)
        self.asm.store(write, addr)
        self.asm.load(observed, addr)
        self.asm.ror(observed, (self.decoy_counter % 63) + 1)
        self.asm.xor(observed, write)
        self.decoy_counter += 1

    def pad_to(
        self,
        checkpoint: int,
        *,
        allowed_registers: tuple[int, ...] = tuple(range(16)),
    ) -> None:
        if self.asm.checkpoint > checkpoint:
            raise RuntimeError(f"program passed checkpoint {checkpoint}")
        while self.asm.checkpoint + 5 <= checkpoint:
            remaining = checkpoint - self.asm.checkpoint
            if remaining >= 7 and self.decoy_counter % 6 == 0:
                self._emit_camouflage(allowed_registers)
                self.decoy_counter += 1
            else:
                self._emit_decoy(allowed_registers)
        while self.asm.checkpoint < checkpoint:
            self.asm.nop()


def load_flag(seed: int) -> bytes:
    flag_file = os.environ.get("SRW_FLAG_FILE")
    if flag_file:
        raw = Path(flag_file).read_bytes().rstrip(b"\r\n")
    else:
        token = hashlib.sha256(f"selective-rewind-development:{seed}".encode()).hexdigest()[:32]
        raw = f"SHA{{{token}}}".encode()
    if not (raw.startswith(b"SHA{") and raw.endswith(b"}") and 8 <= len(raw) <= 192):
        raise ValueError("flag must be 8..192 bytes and use SHA{...} format")
    return raw


def choose_targets(rng: random.Random) -> tuple[list[int], int]:
    targets = []
    cursor = rng.randrange(1100, 1451)
    for _ in range(FAULT_COUNT):
        cursor += rng.randrange(1350, 1901)
        targets.append(cursor)
    final = targets[-1] + rng.randrange(1900, 2601)
    return targets, final


def write_lossy_trace(path: Path, trace, seed: int) -> None:
    rolling = hashlib.sha256(struct.pack("<Q", seed) + b":lossy-bus-v3").digest()
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write("epoch,checkpoint_bucket,event_mix,dirty_transitions,rolling_digest\n")
        for epoch, start in enumerate(range(0, len(trace), 256)):
            group = trace[start:start + 256]
            histogram: dict[str, int] = {}
            for row in group:
                histogram[row.operation] = histogram.get(row.operation, 0) + 1
            event_material = "|".join(
                f"{name}:{histogram[name]}" for name in sorted(histogram)
            ).encode()
            transitions = sum(row.dirty_before != row.dirty_after for row in group)
            event_mix = hashlib.sha256(event_material).hexdigest()[:4]
            quantized = min(255, ((transitions + 8) // 16) * 16)
            rolling = hashlib.sha256(rolling + event_material + bytes([quantized])).digest()
            output.write(f"{epoch},{start // 512},{event_mix},{quantized},{rolling.hex()[:16]}\n")


def generate_image(root: Path, seed: int, variant: int) -> dict[str, object]:
    rng = random.Random(seed)
    camouflage_names = [f"camouflage_{index}" for index in range(8)]
    names = [
        "raw_auth", "normalized_auth", "session_auth", "effective_auth", "reason",
        "raw_uid", "normalized_uid", "session_uid", "effective_uid",
        "raw_generation", "effective_generation", "raw_lease", "effective_lease",
        "verdict_auth", "verdict_uid", "audit_work", "audit_actual", "audit_reference",
        "result",
        *camouflage_names,
    ]
    selected = rng.sample(range(LINE_COUNT), len(names) + 176)
    layout = dict(zip(names, selected[:len(names)]))
    decoy_lines = selected[len(names):]
    memory = bytearray(rng.randbytes(MEM_SIZE))

    for index, line in enumerate(decoy_lines[:128]):
        put_u64(memory, line_addr(line), (0, 1, 7, 8, 1000, 0xF, 0x3)[index % 7])
        put_u64(memory, line_addr(line, 8), derived_u64(f"plausible-state-{variant}", index))

    addresses = {name: line_addr(line) for name, line in layout.items()}
    initial_values = {
        "raw_auth": 1, "normalized_auth": 0, "session_auth": 0, "effective_auth": 0,
        "reason": 1, "raw_uid": 0, "normalized_uid": 1000, "session_uid": 1000,
        "effective_uid": 1000, "raw_generation": 7, "effective_generation": 8,
        "raw_lease": 1, "effective_lease": 0, "verdict_auth": 0, "verdict_uid": 1000,
    }
    for name, value in initial_values.items():
        put_u64(memory, addresses[name], value)
    for name in camouflage_names:
        put_u64(memory, addresses[name], 0)

    admin_midstate = compute_head(1, 0)
    failure_midstate = compute_head(0, 1000)
    for lane, value in enumerate(admin_midstate):
        put_u64(memory, addresses["audit_actual"] + lane * 8, value)
        put_u64(memory, addresses["audit_work"] + lane * 8, derived_u64(f"work-{variant}", lane))
        put_u64(memory, addresses["audit_reference"] + lane * 8, derived_u64(f"ref-{variant}", lane))
    initial_result = (
        0, 1000, 8, 1, 0,
        derived_u64("result-a", variant), derived_u64("result-b", variant),
    )
    for index, value in enumerate(initial_result):
        put_u64(memory, addresses["result"] + index * 8, value)

    targets, final_checkpoint = choose_targets(rng)
    camouflage_addresses = [addresses[name] for name in camouflage_names]
    pg = ProgramGenerator(rng, decoy_lines, camouflage_addresses, variant)
    asm = pg.asm

    pg.pad_to(targets[0] - 2)
    auth_regs = rng.sample(range(13), 5)
    asm.movi(auth_regs[0], 0)
    checkpoint_auth = asm.store(auth_regs[0], addresses["raw_auth"])
    asm.load(auth_regs[1], addresses["raw_auth"])
    asm.store(auth_regs[1], addresses["normalized_auth"])
    asm.load(auth_regs[2], addresses["normalized_auth"])
    asm.store(auth_regs[2], addresses["session_auth"])
    asm.load(auth_regs[3], addresses["session_auth"])
    asm.store(auth_regs[3], addresses["effective_auth"])
    asm.movi(auth_regs[4], 1)
    asm.sub(auth_regs[4], auth_regs[3])
    asm.store(auth_regs[4], addresses["reason"])
    for field in ("raw_auth", "normalized_auth", "session_auth", "effective_auth", "reason"):
        asm.flush(addresses[field])

    pg.pad_to(targets[1] - 2)
    uid_regs = rng.sample(range(13), 4)
    asm.movi(uid_regs[0], 1000)
    checkpoint_uid = asm.store(uid_regs[0], addresses["raw_uid"])
    asm.load(uid_regs[1], addresses["raw_uid"])
    asm.store(uid_regs[1], addresses["normalized_uid"])
    asm.load(uid_regs[2], addresses["normalized_uid"])
    asm.store(uid_regs[2], addresses["session_uid"])
    asm.load(uid_regs[3], addresses["session_uid"])
    asm.store(uid_regs[3], addresses["effective_uid"])
    for field in ("raw_uid", "normalized_uid", "session_uid", "effective_uid"):
        asm.flush(addresses[field])

    pg.pad_to(targets[2] - 2)
    generation_regs = rng.sample(range(13), 2)
    asm.movi(generation_regs[0], 8)
    checkpoint_generation = asm.store(generation_regs[0], addresses["raw_generation"])
    asm.load(generation_regs[1], addresses["raw_generation"])
    asm.store(generation_regs[1], addresses["effective_generation"])
    asm.flush(addresses["raw_generation"])
    asm.flush(addresses["effective_generation"])

    pg.pad_to(targets[3] - 2)
    lease_regs = rng.sample(range(13), 2)
    asm.movi(lease_regs[0], 0)
    checkpoint_lease = asm.store(lease_regs[0], addresses["raw_lease"])
    asm.load(lease_regs[1], addresses["raw_lease"])
    asm.store(lease_regs[1], addresses["effective_lease"])
    asm.flush(addresses["raw_lease"])
    asm.flush(addresses["effective_lease"])

    audit_prefix_instructions = 2 + 8 + 8 + 5
    pg.pad_to(targets[4] - audit_prefix_instructions - 1)
    asm.load(0, addresses["verdict_auth"])
    asm.load(1, addresses["verdict_uid"])
    for lane, value in enumerate(IV):
        emit_store_immediate(asm, 15, addresses["audit_work"] + lane * 8, value)
    emit_head(asm, addresses["audit_work"], 0, 1)
    asm.load(0, addresses["effective_auth"])
    asm.load(1, addresses["effective_uid"])
    asm.load(2, addresses["effective_generation"])
    asm.load(3, addresses["reason"])
    asm.load(4, addresses["effective_lease"])
    checkpoint_audit = asm.memcpy(addresses["audit_actual"], addresses["audit_work"], 32)

    tail_inputs = [0, 1, 2, 3, 4]
    emit_tail(asm, addresses["audit_actual"], tail_inputs)
    asm.flush(addresses["audit_actual"])
    for lane, value in enumerate(IV):
        emit_store_immediate(asm, 15, addresses["audit_reference"] + lane * 8, value)
    emit_head(asm, addresses["audit_reference"], 0, 1)
    emit_tail(asm, addresses["audit_reference"], tail_inputs)
    asm.flush(addresses["audit_reference"])

    for lane, reg in enumerate((5, 6, 7, 8)):
        asm.load(reg, addresses["audit_actual"] + lane * 8)
    asm.xor(5, 6)
    asm.xor(5, 7)
    asm.xor(5, 8)
    for lane, reg in enumerate((9, 10, 11, 12)):
        asm.load(reg, addresses["audit_reference"] + lane * 8)
    asm.xor(9, 10)
    asm.xor(9, 11)
    asm.xor(9, 12)

    for field in ("effective_auth", "effective_uid", "effective_generation", "reason", "effective_lease"):
        asm.flush(addresses[field])

    final_instructions = 15 + 2 * len(camouflage_names)
    pg.pad_to(final_checkpoint - final_instructions, allowed_registers=(13, 14, 15))
    result_fields = (
        "effective_auth", "effective_uid", "effective_generation", "reason", "effective_lease"
    )
    for reg, field in enumerate(result_fields):
        asm.load(reg, addresses[field])
    # Every camouflage chain is zero in fault-free and intended executions.
    # Mixing it into authenticated keeps all chains in a conservative slice
    # without changing the protected result.
    for name in camouflage_names:
        asm.load(15, addresses[name])
        asm.xor(0, 15)
    for reg, _field in enumerate(result_fields):
        asm.store(reg, addresses["result"] + reg * 8)
    asm.store(5, addresses["result"] + 40)
    asm.store(9, addresses["result"] + 48)
    asm.xor(13, 13)
    asm.xor(14, 14)
    asm.halt(addresses["result"])

    intended = [
        (checkpoint_auth, layout["raw_auth"]),
        (checkpoint_uid, layout["raw_uid"]),
        (checkpoint_generation, layout["raw_generation"]),
        (checkpoint_lease, layout["raw_lease"]),
        (checkpoint_audit, layout["audit_actual"]),
    ]
    if [checkpoint for checkpoint, _line in intended] != targets or asm.checkpoint != final_checkpoint:
        raise RuntimeError("checkpoint layout drifted")

    write_image(root / "initial_state.bin", bytes(memory), seed)
    write_program(root / "program.bin", asm.instructions, seed)
    normal_vm = VM(bytes(memory), asm.instructions)
    normal_result = normal_vm.run(record_trace=True)
    solved_result = VM(bytes(memory), asm.instructions).run(intended)
    if normal_result["success"] or not solved_result["success"]:
        raise RuntimeError(f"invalid generated workflow: {normal_result=} {solved_result=}")
    write_lossy_trace(root / "bus.trace", normal_vm.trace, seed)
    (root / "plan.template.json").write_text(
        json.dumps(
            {"version": 3, "faults": [{"checkpoint": index + 1, "line": 0} for index in range(5)]},
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    return {
        "seed": seed,
        "layout": layout,
        "instructions": len(asm.instructions),
        "intended_plan": [{"checkpoint": cp, "line": line} for cp, line in intended],
        "normal_result": normal_result,
        "solved_result": solved_result,
        "failure_midstate": [f"0x{value:016x}" for value in failure_midstate],
        "admin_midstate": [f"0x{value:016x}" for value in admin_midstate],
    }


def main() -> None:
    seed = int(os.environ.get("SRW_SEED", str(DEFAULT_SEED)), 0)
    handout = HANDOUT
    generated = ROOT / "solution" / "generated"
    handout.mkdir(parents=True, exist_ok=True)
    if not (handout / "replay_vm").is_file():
        raise RuntimeError("run make build before generation")

    for child in handout.iterdir():
        if child.name == "replay_vm":
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
    for image_name in IMAGE_NAMES:
        image_dir = handout / image_name
        image_dir.mkdir()
    if generated.exists():
        shutil.rmtree(generated)
    generated.mkdir(parents=True)

    metadata: dict[str, dict[str, object]] = {}
    for variant, image_name in enumerate(IMAGE_NAMES):
        image_seed = int.from_bytes(
            hashlib.sha256(struct.pack("<Q", seed) + image_name.encode()).digest()[:8], "little"
        )
        metadata[image_name] = generate_image(handout / image_name, image_seed, variant)

    flag = load_flag(seed)
    key_material = bytearray(KDF_DOMAIN)
    for image_name in IMAGE_NAMES:
        item = metadata[image_name]
        faults = [(row["checkpoint"], row["line"]) for row in item["intended_plan"]]
        key_material += image_name.encode() + b"\x00"
        key_material += canonical_plan(faults)
        key_material += bytes.fromhex(item["solved_result"]["digest"])
    key = hashlib.sha256(key_material).digest()
    nonce = hashlib.sha256(struct.pack("<Q", seed) + b":fleet-flag-nonce:v3").digest()[:12]
    encrypted = AESGCM(key).encrypt(nonce, flag, AAD)
    (handout / "flag.enc").write_bytes(b"SRW3" + nonce + encrypted)

    public_images = {}
    for image_name in IMAGE_NAMES:
        image_dir = handout / image_name
        public_images[image_name] = {
            "instructions": metadata[image_name]["instructions"],
            "program_sha256": hashlib.sha256((image_dir / "program.bin").read_bytes()).hexdigest(),
            "initial_state_sha256": hashlib.sha256((image_dir / "initial_state.bin").read_bytes()).hexdigest(),
            "bus_trace_sha256": hashlib.sha256((image_dir / "bus.trace").read_bytes()).hexdigest(),
        }
    manifest = {
        "challenge": "selective-state-rewind",
        "version": 3,
        "images": public_images,
        "faults_per_image": FAULT_COUNT,
        "line_count": LINE_COUNT,
        "line_size": LINE_SIZE,
        "cache_lines": 32,
        "replay_receipt": {
            "valid_wrong_plan": '{"success":false}',
            "valid_exact_plan": '{"success":true}',
            "final_state_digest": "created only for an exact successful plan",
        },
        "replay_vm_sha256": hashlib.sha256((handout / "replay_vm").read_bytes()).hexdigest(),
        "flag_enc_sha256": hashlib.sha256((handout / "flag.enc").read_bytes()).hexdigest(),
        "flag_seal": {
            "container_magic_ascii": "SRW3",
            "nonce_bytes": 12,
            "tag_bytes": 16,
            "aead": "AES-256-GCM",
            "aad_ascii": AAD.decode("ascii"),
            "key_hash": "SHA-256",
            "kdf_domain_ascii": KDF_DOMAIN[:-1].decode("ascii"),
            "kdf_domain_has_trailing_nul": True,
            "image_order": list(IMAGE_NAMES),
            "canonical_plan": (
                "ASCII PLN3, then exactly five strictly increasing records: "
                "checkpoint uint32 little-endian followed by line uint16 little-endian"
            ),
            "key_material": (
                "domain || 00 ||, for each image in image_order: image_name ASCII || 00 || "
                "canonical_plan || 32 raw bytes decoded from final_state.digest"
            ),
        },
    }
    (handout / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (generated / "metadata.json").write_text(
        json.dumps(
            {"seed": seed, "images": metadata, "flag_sha256": hashlib.sha256(flag).hexdigest()},
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    (generated / "intended_plan.json").write_text(
        json.dumps(
            {"version": 3, "images": {name: metadata[name]["intended_plan"] for name in IMAGE_NAMES}},
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print("generated three independent images; five causally required faults per image")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Selective Rewind inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after generating, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    main()
    if arguments.publish:
        publish_handout()
