from __future__ import annotations

import argparse
import binascii
import json
import random
import shutil
import struct
import subprocess
from pathlib import Path

from app.core import VaultOracle, layout_state


ROOT = Path(__file__).resolve().parent
HANDOUT = ROOT / ".build" / "for_user"
PUBLIC_HANDOUT = ROOT.parent / "for_user"
PRIVATE = ROOT / "private"
ALPHABET = "0123456789abcdef"
PAYLOAD = "a1b2c3d4e5f6"
STYLE_CONSTANTS = [0x6D2B79F5, 0xA511E9B3, 0x9E3779B9, 0xC0DEC0DE]


def publish_handout() -> None:
    """Copy a complete admin-side build into the public handout directory."""
    if not HANDOUT.is_dir():
        raise RuntimeError("admin handout build is missing")
    if PUBLIC_HANDOUT.exists():
        if PUBLIC_HANDOUT.is_symlink() or not PUBLIC_HANDOUT.is_dir():
            raise RuntimeError(f"refusing to replace non-directory release path: {PUBLIC_HANDOUT}")
        shutil.rmtree(PUBLIC_HANDOUT)
    shutil.copytree(HANDOUT, PUBLIC_HANDOUT)


def encode_u32(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def custom_section(name: bytes, payload: bytes) -> bytes:
    body = encode_u32(len(name)) + name + payload
    return b"\x00" + encode_u32(len(body)) + body


def build_schema_wasm(
    payload_length: int,
    alphabet: str,
    flag_format: str,
    calibration_note: str,
    samples: list[tuple[int, int, int, int, int]],
) -> bytes:
    alphabet_raw = alphabet.encode("ascii")
    format_raw = flag_format.encode("ascii")
    note_raw = calibration_note.encode("utf-8")
    public = (
        b"VBM1"
        + bytes([payload_length, len(alphabet_raw), 1, len(format_raw)])
        + alphabet_raw
        + format_raw
    )
    calibration = b"VBS1" + struct.pack("<HH", len(note_raw), len(samples)) + note_raw
    calibration += b"".join(
        struct.pack("<IIBBH", counter, seed, style, filler, size)
        for counter, seed, style, filler, size in samples
    )
    type_payload = b"\x01\x60\x00\x01\x7f"
    function_payload = b"\x01\x00"
    export_payload = b"\x01\x01v\x00\x00"
    code_payload = b"\x01\x04\x00\x41\x01\x0b"
    return (
        b"\x00asm\x01\x00\x00\x00"
        + custom_section(b"public", public)
        + custom_section(b"samples", calibration)
        + b"\x01" + encode_u32(len(type_payload)) + type_payload
        + b"\x03" + encode_u32(len(function_payload)) + function_payload
        + b"\x07" + encode_u32(len(export_payload)) + export_payload
        + b"\x0a" + encode_u32(len(code_payload)) + code_payload
    )


def main() -> None:
    print("[1/4] 출력 디렉터리 초기화")
    if HANDOUT.exists():
        for child in HANDOUT.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        HANDOUT.mkdir(parents=True)
    if PRIVATE.exists():
        shutil.rmtree(PRIVATE)
    PRIVATE.mkdir(parents=True)

    print("[2/4] 비밀 레코드 생성")
    crc = binascii.crc_hqx(PAYLOAD.encode(), 0xFFFF)
    flag = f"SHA{{{PAYLOAD}-{crc:04x}}}"
    records = [
        f"recovery={flag}",
        "recovery=SHA{a1b2c9aa1122-dead}",
        "recovery=SHA{a1b2c3d4ffff-beef}",
        "recovery=SHA{f00dbabe1234-cafe}",
    ]
    private = {
        "flag": flag,
        "payload": PAYLOAD,
        "records": records,
        "layout_records": [1, 3, 0, 2],
        "canonical_layout": 2,
        "bucket_size": 16,
        "request_budget": 16000,
        "style_constants": STYLE_CONSTANTS,
        "aes_key": random.Random(0xB0A7DA7A).randbytes(32).hex(),
        "padding_key": random.Random(0xB0A7DA7B).randbytes(32).hex(),
    }
    (PRIVATE / "config.json").write_text(json.dumps(private, indent=2), encoding="utf-8")

    print("[3/4] 플레이어 분석 파일 생성")
    oracle = VaultOracle()
    calibration_samples: list[tuple[int, int, int, int, int]] = []
    calibration_note = ""
    for suffix_length in range(32):
        candidate_note = "boundary calibration " + "x" * suffix_length
        candidate_samples = []
        for counter in range(64):
            style = 0
            seed = next(
                candidate for candidate in range(4096)
                if layout_state(counter, candidate, style, STYLE_CONSTANTS) == (2, 0)
            )
            size = oracle.export_size(
                candidate_note,
                counter,
                seed,
                style,
                0,
                b"published-calibration-v1",
            )["size"]
            candidate_samples.append((counter, seed, style, 0, size))
        if len({sample[4] for sample in candidate_samples}) > 1:
            calibration_note = candidate_note
            calibration_samples = candidate_samples
            break
    if not calibration_samples:
        raise RuntimeError("could not construct a useful calibration transcript")
    (HANDOUT / "schema.wasm").write_bytes(build_schema_wasm(
        len(PAYLOAD),
        ALPHABET,
        "SHA{<payload>-<crc16>}",
        calibration_note,
        calibration_samples,
    ))
    subprocess.run([
        "gcc", "-std=c11", "-O2", "-static", "-s", "-Wall", "-Wextra",
        "-Wpedantic", "-Werror", str(ROOT / "native" / "layoutgen.c"),
        "-o", str(HANDOUT / "layoutgen"),
    ], check=True)
    (HANDOUT / "api_examples.json").write_text(json.dumps({
        "session": {
            "method": "POST", "path": "/api/session",
            "headers": {"X-Team-Token": "CTFd에서 발급한 팀 토큰"}, "body": {},
        },
        "authenticated_headers": {"X-Team-Session": "session 응답의 session 값"},
        "share": {"method": "POST", "path": "/api/share", "body": {"value": "case-reference=a"}},
        "export": {"method": "POST", "path": "/api/export-size", "body": {"seed": 0, "style": 0, "filler": 0}},
        "export_response": {"size": 224, "counter": 0, "next_counter": 1, "remaining": 15999},
        "measure": {
            "method": "POST", "path": "/api/measure",
            "body": {
                "value": "case-reference=a",
                "exports": [{"seed": 0, "style": 0, "filler": 0}],
            },
            "note": "exports는 1개부터 16개까지 가능하며 내부 측정 수만큼 예산을 사용합니다.",
        },
        "measure_batch": {
            "method": "POST", "path": "/api/measure-batch",
            "body": {
                "measurements": [{
                    "value": "case-reference=a",
                    "exports": [{"seed": 0, "style": 0, "filler": 0}],
                }],
            },
            "note": "measurements는 최대 16개이며 전체 내부 측정 수만큼 예산을 사용합니다.",
        },
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[4/4] 완료")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Vault Boundary inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after building, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    main()
    if arguments.publish:
        publish_handout()
