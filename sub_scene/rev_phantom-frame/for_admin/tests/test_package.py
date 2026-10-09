#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import subprocess
import sys

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError

HERE = Path(__file__).resolve().parent
ADMIN = HERE.parent
ROOT = ADMIN.parent
USER = ROOT / "for_user"
SOLUTION = ADMIN / "solution"


def run(command: list[str], *, cwd: Path, expected: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected:
        raise AssertionError(
            f"{command} returned {result.returncode}, expected {expected}: "
            f"{result.stderr.decode(errors='replace')}"
        )
    return result


def main() -> None:
    required = [
        "phantom_vm",
        "checker",
        "unwrap",
        "runtime.snap",
        "candidate.pbc",
        "transcript.commit",
        "flag.enc",
        "run.cfg",
        "README.txt",
    ]
    for name in required:
        assert (USER / name).is_file(), name
    for name in ("alpha.pgo", "beta.pgo", "gamma.pgo"):
        assert (USER / "profiles" / name).is_file()
    for name in ("safe.pbc", "osr_demo.pbc", "exception_demo.pbc"):
        assert (USER / "samples" / name).is_file()

    private_flag = (ADMIN / "flag.txt").read_bytes().strip()
    for path in USER.rglob("*"):
        if path.is_file():
            assert private_flag not in path.read_bytes(), f"plaintext leaked into {path}"

    safe_candidate = (USER / "samples" / "safe.pbc").read_bytes()
    original_config = (USER / "run.cfg").read_bytes()
    try:
        (USER / "candidate.pbc").write_bytes(safe_candidate)
        result = run([str(USER / "phantom_vm")], cwd=USER)
        assert b"sink=denied" in result.stdout
        result = run([str(USER / "checker")], cwd=USER, expected=1)
        assert result.stderr == b"optimized rejected\n"

        for sample in ("safe.pbc", "osr_demo.pbc", "exception_demo.pbc"):
            (USER / "run.cfg").write_text(
                f"mode=interpreter\nprogram=samples/{sample}\ntrace=off\n",
                encoding="ascii",
            )
            result = run([str(USER / "phantom_vm")], cwd=USER)
            assert b"completed" in result.stdout

        run(["python3", str(SOLUTION / "build_candidate.py")], cwd=SOLUTION)
        (USER / "run.cfg").write_text(
            "mode=all\nprogram=candidate.pbc\ntrace=coarse\n", encoding="ascii"
        )
        result = run([str(USER / "phantom_vm")], cwd=USER)
        assert result.stdout.count(b"sink=accepted") >= 3
        assert b"reference: completed, sink=denied" in result.stdout

        result = run([str(USER / "checker")], cwd=USER)
        assert b"proof accepted" in result.stdout
        unwrap = run([str(USER / "unwrap")], cwd=USER)
        assert unwrap.stdout.strip() == private_flag
        independent = run(["python3", str(SOLUTION / "decrypt.py")], cwd=SOLUTION)
        assert independent.stdout.strip() == private_flag

        # Local alpha-renaming is canonical: moving both colliding locals from
        # slot 13 to slot 12 remains the same semantic proof.
        sys.path.insert(0, str(ADMIN / "tools"))
        sys.path.insert(0, str(SOLUTION))
        from recover_format import recover_opcodes
        from synthesize_collision_net import synthesize

        renamed = synthesize(local_slot=12).assemble(recover_opcodes())
        (USER / "candidate.pbc").write_bytes(renamed)
        run([str(USER / "checker")], cwd=USER)
        renamed_unwrap = run([str(USER / "unwrap")], cwd=USER)
        assert renamed_unwrap.stdout.strip() == private_flag

        receipt = (USER / "receipt.bin").read_bytes()
        tampered = bytearray(receipt)
        tampered[24] ^= 1
        (USER / "receipt.bin").write_bytes(tampered)
        run([str(USER / "unwrap")], cwd=USER, expected=1)
        (USER / "receipt.bin").write_bytes(receipt)

        # Regression: substituting the public commitment for the raw transcript
        # must not produce the AEAD key.
        enc = (USER / "flag.enc").read_bytes()
        commitment = (USER / "transcript.commit").read_bytes()
        salt, nonce, ciphertext = enc[16:48], enc[48:72], enc[72:]
        seals = [receipt[168 + 32 * i : 200 + 32 * i] for i in range(3)]
        prk = hmac.new(salt, commitment + b"".join(seals), hashlib.sha256).digest()
        shortcut_key = hmac.new(prk, b"phantom-frame-v1\x01", hashlib.sha256).digest()
        try:
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, enc[:72], nonce, shortcut_key
            )
        except CryptoError:
            pass
        else:
            raise AssertionError("commitment shortcut decrypted the flag")
    finally:
        (USER / "candidate.pbc").write_bytes(safe_candidate)
        (USER / "run.cfg").write_bytes(original_config)
        (USER / "receipt.bin").unlink(missing_ok=True)
    print("package tests passed")


if __name__ == "__main__":
    main()
