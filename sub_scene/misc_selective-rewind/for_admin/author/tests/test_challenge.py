from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HANDOUT = ROOT / ".build" / "for_user"
AUTHOR = ROOT / "author"
PROGRAM_SRC = AUTHOR / "program_src"
SOLUTION = ROOT / "solution"
SOLVER = SOLUTION / "solver"
sys.path.insert(0, str(PROGRAM_SRC))
sys.path.insert(0, str(SOLVER))

from decrypt_flag import IMAGE_NAMES, decrypt  # noqa: E402
from isa import (  # noqa: E402
    LINE_COUNT,
    LINE_SIZE,
    OP_HASHSTEP,
    OP_LOAD,
    OP_MEMCPY,
    OP_MOVI,
    OP_STORE,
    read_image,
    read_program,
)
from vm_model import VM  # noqa: E402
from taint import backward_slice  # noqa: E402


def privileged(result: dict) -> bool:
    return bool(
        result["halted"]
        and result["authenticated"] == 1
        and result["uid"] == 0
        and result["generation"] == 7
        and result["reason"] == 0
        and result["lease"] == 1
        and result["audit_valid"]
        and result["faults_consumed"] == 5
    )


class GeneratedChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = json.loads((SOLUTION / "generated" / "metadata.json").read_text())
        cls.images = {}
        for image_name in IMAGE_NAMES:
            image_dir = HANDOUT / image_name
            program_meta, instructions = read_program(image_dir / "program.bin")
            _seed, memory = read_image(image_dir / "initial_state.bin")
            faults = [
                (item["checkpoint"], item["line"])
                for item in cls.metadata["images"][image_name]["intended_plan"]
            ]
            cls.images[image_name] = (program_meta, instructions, memory, faults)

    @classmethod
    def replay(cls, image_name: str, faults) -> dict:
        metadata, instructions, memory, _intended = cls.images[image_name]
        return VM(memory, instructions, metadata["entry"], metadata["max_steps"]).run(faults)

    def test_01_normal_execution_fails_on_every_image(self) -> None:
        for image_name in IMAGE_NAMES:
            with self.subTest(image=image_name):
                result = self.replay(image_name, [])
                self.assertFalse(privileged(result))
                self.assertEqual(
                    (result["authenticated"], result["uid"], result["generation"],
                     result["reason"], result["lease"]),
                    (0, 1000, 8, 1, 0),
                )

    def test_02_all_five_faults_are_required(self) -> None:
        for image_name in IMAGE_NAMES:
            faults = self.images[image_name][3]
            for subset in combinations(faults, 4):
                with self.subTest(image=image_name, omitted=set(faults) - set(subset)):
                    self.assertFalse(privileged(self.replay(image_name, subset)))

    def test_03_intended_plans_succeed(self) -> None:
        for image_name in IMAGE_NAMES:
            faults = self.images[image_name][3]
            result = self.replay(image_name, faults)
            self.assertTrue(result["success"])
            expected = self.metadata["images"][image_name]["solved_result"]["digest"]
            self.assertEqual(result["digest"], expected)

    def test_04_coordinates_cannot_be_copied_between_images(self) -> None:
        plans = [tuple(self.images[name][3]) for name in IMAGE_NAMES]
        self.assertEqual(len(set(plans)), 3)
        for source, target in zip(IMAGE_NAMES, IMAGE_NAMES[1:] + IMAGE_NAMES[:1]):
            self.assertFalse(privileged(self.replay(target, self.images[source][3])))

    def test_05_neighboring_checkpoints_and_wrong_lines_fail(self) -> None:
        for image_name in IMAGE_NAMES:
            faults = self.images[image_name][3]
            for index, (checkpoint, line) in enumerate(faults):
                for replacement in ((checkpoint - 1, line), (checkpoint + 1, line),
                                    (checkpoint, (line + 1) % LINE_COUNT),
                                    (checkpoint, (line + 257) % LINE_COUNT)):
                    changed = faults.copy()
                    changed[index] = replacement
                    changed.sort()
                    with self.subTest(image=image_name, index=index, replacement=replacement):
                        self.assertFalse(privileged(self.replay(image_name, changed)))

    def test_06_native_vm_matches_python_model(self) -> None:
        for image_name in IMAGE_NAMES:
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                source = HANDOUT / image_name
                for filename in ("program.bin", "initial_state.bin"):
                    shutil.copy2(source / filename, work / filename)
                faults = self.images[image_name][3]
                plan = {"version": 3, "faults": [
                    {"checkpoint": checkpoint, "line": line} for checkpoint, line in faults
                ]}
                (work / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
                completed = subprocess.run(
                    [str(HANDOUT / "replay_vm")], cwd=work, capture_output=True, text=True
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                native = json.loads((work / "result.json").read_text())
                model = self.replay(image_name, faults)
                self.assertEqual(native, {"success": True})
                self.assertTrue(model["success"])
                self.assertEqual((work / "result.json").read_bytes(), b'{"success":true}\n')
                self.assertEqual((work / "final_state.digest").read_text().strip(), model["digest"])

    def test_06b_all_valid_wrong_plans_have_one_identical_observation(self) -> None:
        expected = b'{"success":false}\n'
        for image_index, image_name in enumerate(IMAGE_NAMES):
            source = HANDOUT / image_name
            metadata, _instructions, _memory, intended = self.images[image_name]
            last_checkpoint = metadata["max_steps"]
            rng = random.Random(0x5E1EC71E + image_index)
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                for filename in ("program.bin", "initial_state.bin"):
                    shutil.copy2(source / filename, work / filename)

                # The four coordinates after max_steps can never execute.  On
                # the old release this isolated one real candidate and exposed
                # its policy-field and full-memory digest delta.
                probes = [
                    [site, *((last_checkpoint + offset, 511) for offset in range(1, 5))]
                    for site in intended
                ]
                # Also cover arbitrary isolated candidates and ordinary
                # five-coordinate wrong plans, not just mutations of the key.
                for _ in range(128):
                    site = (rng.randrange(1, last_checkpoint + 1), rng.randrange(LINE_COUNT))
                    probes.append([
                        site,
                        *((last_checkpoint + offset, rng.randrange(LINE_COUNT))
                          for offset in range(1, 5)),
                    ])
                for _ in range(64):
                    checkpoints = sorted(rng.sample(range(1, last_checkpoint + 1), 5))
                    probes.append([(checkpoint, rng.randrange(LINE_COUNT)) for checkpoint in checkpoints])

                for probe_index, faults in enumerate(probes):
                    if tuple(faults) == tuple(intended):
                        continue
                    plan = {"version": 3, "faults": [
                        {"checkpoint": checkpoint, "line": line}
                        for checkpoint, line in faults
                    ]}
                    (work / "plan.json").write_text(
                        json.dumps(plan), encoding="utf-8"
                    )
                    completed = subprocess.run(
                        [str(HANDOUT / "replay_vm")],
                        cwd=work,
                        capture_output=True,
                    )
                    self.assertEqual(
                        (completed.returncode, completed.stdout, completed.stderr),
                        (0, b"", b""),
                        f"{image_name}:probe-{probe_index}",
                    )
                    self.assertEqual(
                        (work / "result.json").read_bytes(),
                        expected,
                        f"{image_name}:probe-{probe_index}",
                    )
                    self.assertFalse(
                        (work / "final_state.digest").exists(),
                        f"{image_name}:probe-{probe_index}",
                    )

    def test_07_native_parser_requires_unambiguous_v3_five_fault_plan(self) -> None:
        bad_plans = [
            '{"version":3,"faults":[]}',
            '{"version":1,"faults":[{"checkpoint":1,"line":0},{"checkpoint":2,"line":0},{"checkpoint":3,"line":0},{"checkpoint":4,"line":0},{"checkpoint":5,"line":0}]}',
            '{"version":3,"faults":[{"checkpoint":1,"line":0},{"checkpoint":2,"line":0},{"checkpoint":3,"line":0},{"checkpoint":4,"line":0},{"checkpoint":5,"line":0}],"extra":0}',
            '{"version":3,"version":3,"faults":[{"checkpoint":1,"line":0},{"checkpoint":2,"line":0},{"checkpoint":3,"line":0},{"checkpoint":4,"line":0},{"checkpoint":5,"line":0}]}',
            '{"version":3,"faults":[{"checkpoint":2,"line":0},{"checkpoint":1,"line":0},{"checkpoint":3,"line":0},{"checkpoint":4,"line":0},{"checkpoint":5,"line":0}]}',
        ]
        source = HANDOUT / IMAGE_NAMES[0]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for filename in ("program.bin", "initial_state.bin"):
                shutil.copy2(source / filename, work / filename)
            for raw in bad_plans:
                (work / "result.json").write_text('{"success":true}\n', encoding="utf-8")
                (work / "final_state.digest").write_text("00" * 32 + "\n", encoding="ascii")
                (work / "plan.json").write_text(raw, encoding="utf-8")
                completed = subprocess.run(
                    [str(HANDOUT / "replay_vm")], cwd=work, capture_output=True, text=True
                )
                self.assertEqual(completed.returncode, 2, raw)
                self.assertFalse((work / "result.json").exists(), raw)
                self.assertFalse((work / "final_state.digest").exists(), raw)

    def test_08_fleet_receipt_decrypts_flag(self) -> None:
        receipts = {}
        for image_name in IMAGE_NAMES:
            faults = tuple(self.images[image_name][3])
            digest = self.replay(image_name, faults)["digest"]
            receipts[image_name] = (faults, digest)
        flag = decrypt(HANDOUT / "flag.enc", receipts)
        self.assertTrue(flag.startswith(b"SHA{"))
        self.assertEqual(hashlib.sha256(flag).hexdigest(), self.metadata["flag_sha256"])

    def test_09_handout_contains_no_plaintext_flag(self) -> None:
        for path in HANDOUT.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SHA{", path.read_bytes(), str(path.relative_to(HANDOUT)))

    def test_10_only_lossy_traces_are_distributed(self) -> None:
        self.assertFalse(any(
            path.is_file() for path in HANDOUT.rglob("trace.map")
        ))
        for image_name in IMAGE_NAMES:
            header = (HANDOUT / image_name / "bus.trace").read_text().splitlines()[0]
            self.assertNotIn("pc", header)
            self.assertNotIn("line", header)
            self.assertNotIn("address", header)

    def test_11_manifest_hashes_match(self) -> None:
        manifest = json.loads((HANDOUT / "manifest.json").read_text())
        self.assertEqual(manifest["version"], 3)
        self.assertEqual(manifest["faults_per_image"], 5)
        self.assertEqual(
            manifest["replay_receipt"]["valid_wrong_plan"],
            '{"success":false}',
        )
        self.assertIn("only", manifest["replay_receipt"]["final_state_digest"])
        self.assertEqual(
            hashlib.sha256((HANDOUT / "replay_vm").read_bytes()).hexdigest(),
            manifest["replay_vm_sha256"],
        )
        for image_name in IMAGE_NAMES:
            item = manifest["images"][image_name]
            image_dir = HANDOUT / image_name
            for filename, key in (("program.bin", "program_sha256"),
                                  ("initial_state.bin", "initial_state_sha256"),
                                  ("bus.trace", "bus_trace_sha256")):
                self.assertEqual(hashlib.sha256((image_dir / filename).read_bytes()).hexdigest(), item[key])

        seal = manifest["flag_seal"]
        self.assertEqual(seal["container_magic_ascii"], "SRW3")
        self.assertEqual(seal["aead"], "AES-256-GCM")
        self.assertEqual(seal["aad_ascii"], "selective-state-rewind-v3")
        self.assertEqual(seal["key_hash"], "SHA-256")
        self.assertEqual(seal["image_order"], list(IMAGE_NAMES))
        self.assertIn("uint32 little-endian", seal["canonical_plan"])
        self.assertIn("final_state.digest", seal["key_material"])

    def test_12_official_solver_uses_handout_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "handout"
            shutil.copytree(HANDOUT, work)
            shutil.copytree(SOLUTION, work / "solution")
            before = {
                str(path.relative_to(work)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in work.rglob("*") if path.is_file()
            }
            environment = os.environ.copy()
            environment.pop("PYTHONPATH", None)
            environment.pop("SRW_HANDOUT_DIR", None)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["SRW_SOLVER_NO_FLAG"] = "1"
            completed = subprocess.run(
                [sys.executable, str(work / "solution/solver/solve.py")],
                cwd=work,
                capture_output=True,
                text=True,
                env=environment,
                timeout=120,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("flag decrypted and authenticated", completed.stdout)
            after = {
                str(path.relative_to(work)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in work.rglob("*") if path.is_file()
            }
            self.assertEqual(after, before)

    def test_13_release_vm_has_no_runtime_debug_oracle(self) -> None:
        binary = (HANDOUT / "replay_vm").read_bytes()
        for marker in (b"debug.cfg", b"trace_pc=", b"watch_line=", b"cache=hit"):
            self.assertNotIn(marker, binary)

        source = HANDOUT / IMAGE_NAMES[0]
        faults = self.images[IMAGE_NAMES[0]][3]
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for filename in ("program.bin", "initial_state.bin"):
                shutil.copy2(source / filename, work / filename)
            (work / "plan.json").write_text(
                json.dumps({"version": 3, "faults": [
                    {"checkpoint": checkpoint, "line": line}
                    for checkpoint, line in faults
                ]}),
                encoding="utf-8",
            )
            (work / "debug.cfg").write_text(
                "trace_pc=1\ncache=1\nwatch_line=0\n", encoding="ascii"
            )
            completed = subprocess.run(
                [str(HANDOUT / "replay_vm")], cwd=work, capture_output=True, text=True
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse((work / "debug.log").exists())

    def test_14_handout_contains_only_declared_release_files(self) -> None:
        expected = {"flag.enc", "manifest.json", "replay_vm"}
        for image_name in IMAGE_NAMES:
            expected.update({
                f"{image_name}/program.bin",
                f"{image_name}/initial_state.bin",
                f"{image_name}/bus.trace",
                f"{image_name}/plan.template.json",
            })
        actual = {
            str(path.relative_to(HANDOUT))
            for path in HANDOUT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, expected)

    def test_15_local_opcode_signatures_are_deliberately_ambiguous(self) -> None:
        for image_name in IMAGE_NAMES:
            _metadata, instructions, _memory, intended = self.images[image_name]
            sliced = backward_slice(instructions)
            selected = sliced.instruction_indexes
            store_signatures = []
            audit_signatures = []
            old_fixed_register_signatures = []
            for index in range(1, len(instructions) - 1):
                previous, current, following = instructions[index - 1:index + 2]
                if (
                    previous.opcode == OP_MOVI
                    and current.opcode == OP_STORE
                    and following.opcode == OP_LOAD
                    and following.addr == current.addr
                ):
                    store_signatures.append(index)
                    if previous.dst == 0 and current.src == 0 and following.dst == 1:
                        old_fixed_register_signatures.append(index)
                if (
                    current.opcode == OP_MEMCPY
                    and following.opcode == OP_HASHSTEP
                    and current.addr // LINE_SIZE == following.addr // LINE_SIZE
                ):
                    audit_signatures.append(index)
            selected_store = set(store_signatures) & set(selected)
            selected_audit = set(audit_signatures) & set(selected)
            intended_indexes = {checkpoint - 1 for checkpoint, _line in intended}
            with self.subTest(image=image_name):
                self.assertGreaterEqual(len(store_signatures), 500)
                self.assertGreaterEqual(len(old_fixed_register_signatures), 10)
                self.assertGreaterEqual(len(audit_signatures), 100)
                self.assertGreaterEqual(len(selected_store), 40)
                self.assertGreaterEqual(len(selected_audit), 40)
                self.assertFalse(intended_indexes.issubset(set(old_fixed_register_signatures)))


if __name__ == "__main__":
    unittest.main()
