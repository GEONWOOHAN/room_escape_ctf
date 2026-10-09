#!/usr/bin/env python3
"""End-to-end official solve using only the player validation path."""

from pathlib import Path
import subprocess

from build_candidate import main as build_candidate

HERE = Path(__file__).resolve().parent
USER = HERE.parents[1] / "for_user"


def main() -> None:
    candidate = USER / "candidate.pbc"
    receipt = USER / "receipt.bin"
    reference = HERE / "reference_candidate.pbc"
    original = candidate.read_bytes()
    try:
        build_candidate()
        subprocess.run([str(USER / "checker")], cwd=USER, check=True)
        subprocess.run([str(USER / "unwrap")], cwd=USER, check=True)
    finally:
        candidate.write_bytes(original)
        receipt.unlink(missing_ok=True)
        reference.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
