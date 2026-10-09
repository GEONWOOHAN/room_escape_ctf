"""Fleet-receipt key derivation and authenticated flag decryption."""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"selective-state-rewind-v3"
KDF_DOMAIN = b"selective-state-rewind-fleet-receipt-v3\x00"
IMAGE_NAMES = ("image_a", "image_b", "image_c")


def canonical_plan(faults: list[tuple[int, int]]) -> bytes:
    if len(faults) != 5:
        raise ValueError("canonical plans contain exactly five faults")
    encoded = bytearray(b"PLN3")
    previous = -1
    for checkpoint, line in faults:
        if not (1 <= checkpoint <= 0xFFFFFFFF and 0 <= line < 512):
            raise ValueError("fault outside canonical range")
        if checkpoint <= previous:
            raise ValueError("fault checkpoints are not strictly increasing")
        encoded += struct.pack("<IH", checkpoint, line)
        previous = checkpoint
    return bytes(encoded)


def derive_key(receipts: dict[str, tuple[tuple[tuple[int, int], ...], str]]) -> bytes:
    material = bytearray(KDF_DOMAIN)
    if set(receipts) != set(IMAGE_NAMES):
        raise ValueError("all three image receipts are required")
    for image_name in IMAGE_NAMES:
        faults, digest = receipts[image_name]
        material += image_name.encode() + b"\x00"
        material += canonical_plan(list(faults))
        try:
            digest_bytes = bytes.fromhex(digest)
        except ValueError as error:
            raise ValueError(f"{image_name}: invalid final-state digest") from error
        if len(digest_bytes) != 32:
            raise ValueError(f"{image_name}: final-state digest must be 32 bytes")
        material += digest_bytes
    return hashlib.sha256(material).digest()


def decrypt(path: Path, receipts: dict[str, tuple[tuple[tuple[int, int], ...], str]]) -> bytes:
    container = path.read_bytes()
    if len(container) < 4 + 12 + 16 or container[:4] != b"SRW3":
        raise ValueError("invalid flag.enc container")
    nonce = container[4:16]
    try:
        plaintext = AESGCM(derive_key(receipts)).decrypt(nonce, container[16:], AAD)
    except InvalidTag as error:
        raise ValueError("fleet receipt failed AEAD authentication") from error
    if not (plaintext.startswith(b"SHA{") and plaintext.endswith(b"}")):
        raise ValueError("decrypted payload is not a flag")
    return plaintext
