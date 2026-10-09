#!/usr/bin/env python3
"""Player-side reproducer for the recovered three-image fault plans."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from decrypt_flag import IMAGE_NAMES, decrypt  # noqa: E402


PLANS: dict[str, tuple[tuple[int, int], ...]] = {
    "image_a": (
        (2765, 224),
        (4401, 119),
        (6105, 488),
        (7729, 84),
        (9475, 271),
    ),
    "image_b": (
        (3038, 54),
        (4923, 397),
        (6342, 346),
        (8062, 209),
        (9652, 171),
    ),
    "image_c": (
        (2725, 304),
        (4297, 313),
        (5848, 454),
        (7661, 154),
        (9535, 120),
    ),
}


def locate_handout() -> Path:
    configured = os.environ.get("SRW_HANDOUT_DIR")
    candidates = [Path(configured)] if configured else [
        Path.cwd(),
        Path(__file__).resolve().parents[2],
        Path(__file__).resolve().parents[2].parent / "for_user",
    ]
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "replay_vm").is_file() and (resolved / "flag.enc").is_file():
            return resolved
    raise RuntimeError("run from a selective-rewind for_user directory")


def replay(handout: Path, image_name: str, faults: tuple[tuple[int, int], ...]) -> str:
    source = handout / image_name
    with tempfile.TemporaryDirectory(prefix=f"srw-{image_name}-") as directory:
        work = Path(directory)
        for name in ("program.bin", "initial_state.bin", "bus.trace"):
            shutil.copy2(source / name, work / name)
        shutil.copy2(handout / "replay_vm", work / "replay_vm")
        plan = {
            "version": 3,
            "faults": [
                {"checkpoint": checkpoint, "line": line}
                for checkpoint, line in faults
            ],
        }
        (work / "plan.json").write_text(
            json.dumps(plan, separators=(",", ":")), encoding="ascii"
        )
        completed = subprocess.run(
            [str(work / "replay_vm")],
            cwd=work,
            text=True,
            capture_output=True,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr.strip() or "native replay failed")
        result = json.loads((work / "result.json").read_text(encoding="ascii"))
        if result != {"success": True}:
            raise RuntimeError(f"{image_name}: recovered plan was rejected")
        digest = (work / "final_state.digest").read_text(encoding="ascii").strip()
        if len(digest) != 64:
            raise RuntimeError(f"{image_name}: malformed final-state digest")
        return digest


def solve() -> bytes:
    handout = locate_handout()
    receipts = {
        image_name: (PLANS[image_name], replay(handout, image_name, PLANS[image_name]))
        for image_name in IMAGE_NAMES
    }
    return decrypt(handout / "flag.enc", receipts)


def main() -> None:
    flag = solve()
    if os.environ.get("SRW_SOLVER_NO_FLAG") == "1":
        print("flag decrypted and authenticated (output suppressed)")
    else:
        print(flag.decode("ascii"))


if __name__ == "__main__":
    main()
