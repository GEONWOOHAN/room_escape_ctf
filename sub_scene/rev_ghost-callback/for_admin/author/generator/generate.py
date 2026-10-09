#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import argparse
import base64
import hashlib
import json
import random
import shutil
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[2]
AUTHOR = ROOT / "author"
HANDOUT = ROOT / ".build" / "for_user"
PUBLIC_HANDOUT = ROOT.parent / "for_user"
sys.path[:0] = [
    str(AUTHOR),
    str(AUTHOR / "firmware_src"),
    str(AUTHOR / "package_builder"),
    str(AUTHOR / "vendor"),
]
from common_crypto import (
    INSTALL_RECEIPT_MAGIC,
    aead_encrypt,
    ed25519_public_key,
    ed25519_sign,
    semantic_install_receipt,
)
from build_firmware import CALLBACK_COUNT, CHAIN_LENGTH, build, route_forward
from package_format import make_package, make_tar

FLAG = b"SHA{one_semantic_policy_wakes_the_entire_ghost_fleet}"
AAD = b"ghost-callback-fleet-v6"
BUILD_SEEDS = (0x47484131, 0x47484232, 0x47484333)
DEVICE_NAMES = ("a", "b", "c")
SIGNING_SEED = hashlib.sha256(b"ghost-callback-author-signing-key-v3").digest()
COMMON_NONCE = hashlib.sha256(b"ghost-callback-common-calibration-nonce-v3").digest()[:16]
CALIBRATION_KDF_DOMAIN = b"ghost-callback-calibration-proof-v5\x00"
INTENDED_OVERWRITE_PATH = "extras/%EF%BC%8E%EF%BC%8E/profiles/calibration.bin"
INTENDED_POLICY_PATH = "extras/../profiles/calibration.bin"
FINAL_CALIBRATION_PATH = "profiles/calibration.bin"


def reset_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError(f"refusing to replace non-directory build path: {path}")
        shutil.rmtree(path)
    path.mkdir(parents=True)


def publish_handout() -> None:
    """Replace the public handout only after a complete admin-side build."""
    if not HANDOUT.is_dir():
        raise RuntimeError("admin handout build is missing")
    if PUBLIC_HANDOUT.exists():
        if PUBLIC_HANDOUT.is_symlink() or not PUBLIC_HANDOUT.is_dir():
            raise RuntimeError(f"refusing to replace non-directory release path: {PUBLIC_HANDOUT}")
        shutil.rmtree(PUBLIC_HANDOUT)
    shutil.copytree(HANDOUT, PUBLIC_HANDOUT)


def calibration(generation: int, mmio_seed: bytes, permutation_seed: bytes, nonce_material: bytes) -> bytes:
    body = b"CAL1" + struct.pack("<I", generation) + mmio_seed + permutation_seed + nonce_material
    return body + struct.pack("<II", zlib.crc32(body) & 0xFFFFFFFF, 0)


def calibration_seeds(metadata: dict[str, dict[str, object]]) -> tuple[bytes, bytes]:
    """Derive every calibration seed byte from the three recovered route proofs."""
    material = bytearray(CALIBRATION_KDF_DOMAIN)
    for name in DEVICE_NAMES:
        item = metadata[name]
        callbacks = {int(callback["id"]): callback for callback in item["callbacks"]}
        material += name.encode("ascii")
        material += struct.pack("<II", *map(int, item["route_target"]))
        for callback_id in item["real_chain"]:
            callback = callbacks[int(callback_id)]
            material += struct.pack(
                "<BIIIIBB",
                int(callback_id),
                int(callback["expected"]),
                int(callback["following"]),
                *map(int, callback["route_terms"]),
                *map(int, callback["route_rotations"]),
            )
    digest = hashlib.blake2s(material).digest()
    return digest[:16], digest[16:]


def compile_bytecode_variants(source: Path, stem: str) -> list[str]:
    """Build sourceless modules for every supported interpreter available to the author."""
    interpreters: dict[str, str] = {}
    for candidate in (sys.executable, *(shutil.which(name) for name in (
        "python3.14", "python3.13", "python3.12", "python3.11",
    ))):
        if not candidate:
            continue
        completed = subprocess.run(
            [candidate, "-c", "import sys; print(f'{sys.version_info.major}{sys.version_info.minor}')"],
            check=True,
            capture_output=True,
            text=True,
        )
        tag = completed.stdout.strip()
        interpreters.setdefault(tag, candidate)
    if not interpreters:
        raise RuntimeError("no supported CPython interpreter found")

    for stale in HANDOUT.glob(f"{stem}.cpython-*.pyc"):
        stale.unlink()
    (HANDOUT / f"{stem}.pyc").unlink(missing_ok=True)
    for tag, interpreter in sorted(interpreters.items()):
        destination = HANDOUT / f"{stem}.cpython-{tag}.pyc"
        subprocess.run(
            [
                interpreter,
                "-c",
                (
                    "import py_compile,sys; "
                    "py_compile.compile(sys.argv[1], cfile=sys.argv[2], "
                    "dfile=sys.argv[3], doraise=True)"
                ),
                str(source),
                str(destination),
                f"{stem}.py",
            ],
            check=True,
        )
    return sorted(interpreters)


def rotate_right(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def callback_output(metadata: dict[str, object], chain: list[int]) -> bytes:
    regs = list(metadata["initial_regs"])
    output = bytearray()
    by_id = {item["id"]: item for item in metadata["callbacks"]}
    guard = metadata["initial_guard"]
    route = (0, 0)
    for callback_id in chain:
        item = by_id[callback_id]
        if guard != item["expected"]:
            raise RuntimeError("author callback chain guard mismatch")
        constants, shifts = item["constants"], item["shifts"]
        regs[0] = rotate_right(((regs[0] ^ constants[0]) + regs[1]) & 0xFFFFFFFF, shifts[0])
        regs[1] = rotate_right(((regs[1] ^ constants[1]) + regs[2]) & 0xFFFFFFFF, shifts[1])
        regs[2] = rotate_right(((regs[2] ^ constants[2]) + regs[3]) & 0xFFFFFFFF, shifts[2])
        regs[3] = rotate_right(((regs[3] ^ constants[3]) + regs[0]) & 0xFFFFFFFF, shifts[3])
        route = route_forward(route, item["route_terms"], item["route_rotations"])
        output.extend(struct.pack("<II", regs[0], regs[1]))
        guard = item["following"]
    if (
        guard != metadata["terminal_guard"]
        or tuple(route) != tuple(metadata["route_target"])
        or len(chain) != CHAIN_LENGTH
    ):
        raise RuntimeError("author terminal proof mismatch")
    return bytes(output)


def permutation(seed: bytes) -> list[int]:
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


def condition(sample: int, channel: int, window: int, mmio_seed: bytes, targets: list[int]) -> bool:
    return ((sample ^ mmio_seed[channel & 15]) + window) % 257 == targets[channel]


def build_events(chain: list[int], mmio_seed: bytes, permutation_seed: bytes, targets: list[int]) -> list[dict[str, int]]:
    order = permutation(permutation_seed)
    events: list[dict[str, int]] = []
    window, cycle = 0, 100_000
    for callback_id in chain:
        channel = order.index(callback_id)
        sequence: list[tuple[int, int]] | None = None
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
            raise RuntimeError("author MMIO event inversion failed")
        for event_channel, sample in sequence:
            cycle += 3000
            events.append({"cycle": cycle, "channel": event_channel, "sample": sample, "status": 1})
            window = (window + sample) & 255
    return events


def derive_key(
    calibration_data: bytes,
    firmwares: dict[str, bytes],
    outputs: dict[str, bytes],
    install_receipt: bytes,
) -> bytes:
    if len(install_receipt) != 36 or not install_receipt.startswith(INSTALL_RECEIPT_MAGIC):
        raise ValueError("invalid semantic install receipt")
    material = bytearray(b"ghost-callback-fleet-receipt-v6\x00")
    material += hashlib.sha256(calibration_data).digest()
    material += install_receipt[4:]
    for name in DEVICE_NAMES:
        material += (
            name.encode() + hashlib.sha256(firmwares[name]).digest()
            + outputs[name]
        )
    return hashlib.blake2s(material).digest()


def pem(label: str, data: bytes) -> bytes:
    encoded = base64.b64encode(data).decode()
    lines = "\n".join(encoded[index:index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n".encode()


def copy_vendor() -> None:
    destination = HANDOUT / "vendor"
    destination.mkdir(exist_ok=True)
    source = AUTHOR / "vendor"
    source_library = source / "unicorn/lib/libunicorn.so.2"
    destination_library = destination / "unicorn/lib/libunicorn.so.2"
    # Remove dependency families from older releases without replacing the
    # loaded Unicorn directory itself (hgfs may refuse that operation).
    for stale in list(destination.iterdir()):
        if stale.name == "unicorn" or stale.name.startswith("unicorn-"):
            continue
        if stale.is_dir():
            shutil.rmtree(stale, ignore_errors=True)
        else:
            stale.unlink(missing_ok=True)
    if (
        destination_library.is_file()
        and hashlib.sha256(destination_library.read_bytes()).digest()
        == hashlib.sha256(source_library.read_bytes()).digest()
    ):
        # Do not overwrite a shared object that the current interpreter may
        # already have mapped; this also makes repeated deterministic builds cheap.
        for cache in destination.rglob("__pycache__"):
            shutil.rmtree(cache, ignore_errors=True)
        return
    names = ["unicorn"]
    names += [
        item.name for item in source.iterdir()
        if item.name.startswith("unicorn-") and item.name.endswith(".dist-info")
    ]
    for name in names:
        item = source / name
        if item.is_dir():
            shutil.copytree(item, destination / name, dirs_exist_ok=True)
    for disposable in (destination / "unicorn/include", destination / "unicorn/lib/libunicorn.a"):
        if disposable.is_dir():
            shutil.rmtree(disposable)
        elif disposable.exists():
            disposable.unlink()
    for cache in destination.rglob("__pycache__"):
        shutil.rmtree(cache)


def main() -> None:
    reset_directory(HANDOUT)
    firmwares: dict[str, bytes] = {}
    metadata: dict[str, dict[str, object]] = {}

    print("[1/6] three randomized ARM Thumb firmware images", flush=True)
    for name, seed in zip(DEVICE_NAMES, BUILD_SEEDS):
        firmware, item = build(
            seed,
            expected_nonce=COMMON_NONCE,
        )
        firmwares[name] = firmware
        metadata[name] = item
        (HANDOUT / f"firmware_{name}.bin").write_bytes(firmware)

    print("[2/6] signed fleet update package", flush=True)
    initial_calibration = calibration(17, bytes(16), bytes(16), bytes(16))
    required_entries = [
        (f"firmware/firmware_{name}.bin", firmwares[name]) for name in DEVICE_NAMES
    ] + [("profiles/calibration.bin", initial_calibration)]
    manifest_document = {
        "device": "gc-fleet",
        "version": 18,
        "required": [
            {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
            for path, content in required_entries
        ],
        "optional_prefix": "extras/",
    }
    manifest = json.dumps(manifest_document, separators=(",", ":"), ensure_ascii=False).encode()
    public_key = ed25519_public_key(SIGNING_SEED)
    signature = ed25519_sign(SIGNING_SEED, manifest)
    release_entry = ("extras/release.txt", b"fleet stability update 18\n")
    normal_entries = required_entries + [release_entry]
    payload = make_tar(normal_entries)
    package = make_package(manifest, signature, payload)
    public_der = bytes.fromhex("302a300506032b6570032100") + public_key
    public_pem = pem("PUBLIC KEY", public_der)

    print("[3/6] three callback transcripts seal the flag", flush=True)
    mmio_seed, permutation_seed = calibration_seeds(metadata)
    intended_calibration = calibration(18, mmio_seed, permutation_seed, COMMON_NONCE)
    outputs = {
        name: callback_output(metadata[name], metadata[name]["real_chain"])
        for name in DEVICE_NAMES
    }
    install_receipt = semantic_install_receipt(
        "optional", INTENDED_POLICY_PATH, FINAL_CALIBRATION_PATH, intended_calibration
    )
    key = derive_key(
        intended_calibration, firmwares, outputs, install_receipt
    )
    file_nonce = hashlib.blake2s(b"ghost-callback-fleet-flag-nonce-v5", digest_size=12).digest()
    encrypted_flag = b"GCF6" + file_nonce + aead_encrypt(key, file_nonce, FLAG, AAD)

    print("[4/6] updater and fleet runtime build", flush=True)
    extractor_source = AUTHOR / "updater_src" / "extractor.c"
    subprocess.run(
        ["gcc", "-O2", "-s", "-Wall", "-Wextra", "-Werror", "-o", str(HANDOUT / "extractor"), str(extractor_source)],
        check=True,
    )
    copies = {
        AUTHOR / "updater_src" / "updater": HANDOUT / "updater",
        AUTHOR / "device_runner_src" / "device_runner": HANDOUT / "device_runner",
        AUTHOR / "device_runner_src" / "decrypt_flag.py": HANDOUT / "decrypt_flag.py",
        AUTHOR / "common_crypto.py": HANDOUT / "crypto_core.py",
    }
    for source, destination in copies.items():
        shutil.copy2(source, destination)
    updater_versions = compile_bytecode_variants(
        AUTHOR / "updater_src" / "updater_pipeline.py", "updater_pipeline"
    )
    runner_versions = compile_bytecode_variants(
        AUTHOR / "device_runner_src" / "device_runner.py", "device_runner"
    )
    if updater_versions != runner_versions:
        raise RuntimeError("bytecode interpreter set mismatch")

    print("[5/6] offline Unicorn dependency and public artifacts", flush=True)
    copy_vendor()
    (HANDOUT / "normal_update.pkg").write_bytes(package)
    (HANDOUT / "flag.enc").write_bytes(encrypted_flag)
    (HANDOUT / "public_key.pem").write_bytes(public_pem)
    device = {
        "device": "gc-fleet",
        "runtime": {
            "platform": "Linux x86-64",
            "cpython_bytecode_versions": updater_versions,
            "launcher": "selects a matching installed CPython interpreter",
        },
        "architectures": {name: "ARMv7-M Thumb" for name in DEVICE_NAMES},
        "firmware_base": "0x08000000",
        "callback_model": {
            "functions_per_device": CALLBACK_COUNT,
            "required_depth": CHAIN_LENGTH,
            "branching_per_depth": 4,
            "addresses": "pointer-table based and independently randomized",
            "terminal_state": "two coupled 32-bit words; recover the transition from firmware",
        },
        "memory": {
            "flash": ["0x08000000", 65536],
            "sram": ["0x20000000", 65536],
            "sensor_mmio": ["0x40001000", 4096],
            "nvic": ["0xE000E100", 4096],
        },
        "event_limits": {
            "per_device": 512,
            "cycle": 1000000,
            "channel": [0, CALLBACK_COUNT - 1],
            "sample": [0, 255],
            "status_mask": 1,
        },
        "calibration_derivation": {
            "generation": 18,
            "hash": "BLAKE2s-256",
            "domain_hex": CALIBRATION_KDF_DOMAIN.hex(),
            "device_order": list(DEVICE_NAMES),
            "per_device": (
                "ASCII device name || two LE32 route target words || for each selected "
                "callback in route order: U8 id || LE32 expected guard || LE32 following "
                "guard || two LE32 transition terms || U8 first rotation || U8 second rotation"
            ),
            "split": "digest[0:16]=MMIO seed, digest[16:32]=permutation seed",
            "nonce": "the common 16-byte nonce checked by all three firmware images",
        },
        "flag_binding": (
            "semantic install receipt, calibration digest, all three "
            "firmware digests and 160-byte callback transcripts; TAR metadata and equivalent "
            "event schedules are not answer material"
        ),
    }
    (HANDOUT / "device.json").write_text(json.dumps(device, indent=2) + "\n", encoding="utf-8")
    benign = {"events": [
        {"cycle": 1200, "channel": 1, "sample": 84, "status": 0},
        {"cycle": 2450, "channel": 3, "sample": 19, "status": 0},
    ]}
    for name in DEVICE_NAMES:
        (HANDOUT / f"events_{name}.json").write_text(json.dumps(benign, indent=2) + "\n")

    stale_files = (
        "firmware.bin", "events.json", "policy.luac", "callback_output.bin",
        "callback_outputs.bin", "candidate.pkg",
    )
    for filename in stale_files:
        (HANDOUT / filename).unlink(missing_ok=True)
    for generated_directory in (HANDOUT / ".stage", HANDOUT / ".update_work", HANDOUT / "__pycache__"):
        if generated_directory.exists():
            shutil.rmtree(generated_directory)
    for executable in ("updater", "device_runner", "extractor", "decrypt_flag.py"):
        (HANDOUT / executable).chmod(0o755)
    print("[6/6] release generated", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Ghost Callback assets inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after building, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    main()
    if arguments.publish:
        publish_handout()
