from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import tempfile
import unittest
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ["TLF_HANDOUT_DIR"] = str(ROOT / ".build" / "for_user")
import sys
sys.path.insert(0, str(ROOT.parent / "for_user"))

from generator.generate_challenge import (
    FINGERPRINT_MODULUS,
    FIXED_OVERHEAD,
    HANDOUT_DIR,
    PRIVATE_DIR,
    SERVER_IPS,
    SECRET_LENGTHS,
    WORDS_PER_LENGTH,
    NATIVE_DIR,
    batch_fingerprint as generator_batch_fingerprint,
    fingerprint_family,
    generate_challenge,
    layout_family,
    record_layout as generator_record_layout,
)
from solution.solver.solve import (
    CAPTURE_PATHS,
    candidate_secret_vectors,
    decrypt_with_phrases,
    derive_overhead,
    extract_capture,
    recovered_batch_fingerprint,
    recovered_fingerprint_family,
    recovered_layout,
    recovered_layout_family,
    recover_phrase_candidates,
    recover_token_lengths,
)

class ChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        generate_challenge()
        cls.captures = tuple(
            extract_capture(path, server)
            for path, server in zip(CAPTURE_PATHS, SERVER_IPS)
        )
        cls.metadata = json.loads((PRIVATE_DIR / "sessions.json").read_text(encoding="utf-8"))

    @classmethod
    def _get_phrase_candidates(cls) -> list[str]:
        cached = getattr(cls, "_cached_phrase_candidates", None)
        if cached is None:
            vectors = candidate_secret_vectors(cls.captures, FIXED_OVERHEAD)
            cached = []
            for tag, vector in vectors:
                cached.extend(recover_phrase_candidates(tag, vector, cls.captures))
            cls._cached_phrase_candidates = cached
        return cached

    def test_01_two_captures_have_same_24_logical_flows(self) -> None:
        self.assertEqual(len(self.captures[0]), 24)
        self.assertEqual(set(self.captures[0]), set(self.captures[1]))

    def test_01b_capture_endpoint_order_is_independent(self) -> None:
        by_tag: dict[str, dict[int, int]] = {}
        for item in self.metadata["sessions"]:
            by_tag.setdefault(item["tag"], {})[item["capture"]] = item["wire_index"]
        pairs = [tuple(indexes[capture] for capture in (0, 1)) for indexes in by_tag.values()]
        self.assertEqual(len(pairs), 24)
        self.assertGreaterEqual(sum(first != second for first, second in pairs), 20)
        self.assertNotEqual(
            [first for first, _second in pairs],
            [second for _first, second in pairs],
        )

    def test_02_records_batch_one_to_three_tokens(self) -> None:
        layouts = [
            item
            for session in self.metadata["sessions"]
            for item in session["layout"]
        ]
        self.assertTrue(all(1 <= item["count"] <= 3 for item in layouts))
        self.assertTrue(any(item["count"] > 1 for item in layouts))
        self.assertTrue(any(item["pad"] > 0 for item in layouts))

    def test_03_release_models_are_non_queryable_fixed_self_tests(self) -> None:
        for filename in ("record_layout", "batch_model"):
            binary = HANDOUT_DIR / filename
            observations = []
            for supplied in (b"", b"0 1 2\n", b"1 4294967295 63 3 a b c\n", b"garbage\n"):
                completed = subprocess.run([str(binary)], input=supplied, capture_output=True)
                observations.append(
                    (completed.returncode, completed.stdout, completed.stderr)
                )
            self.assertEqual(len(set(observations)), 1, filename)
            returncode, stdout, stderr = observations[0]
            self.assertEqual(returncode, 0, filename)
            self.assertEqual(stderr, b"", filename)
            self.assertIn(b"self-test: ok", stdout, filename)
            for oracle_marker in (b"start=", b"count=", b"pad=", b"fingerprint=", b"window="):
                self.assertNotIn(oracle_marker, stdout, filename)
            # Static libc itself contains generic strings such as "count=";
            # use only challenge-specific calculator markers for binary scans.
            for oracle_marker in (b"start=", b"pad=", b"fingerprint=", b"window="):
                self.assertNotIn(oracle_marker, binary.read_bytes(), filename)
            description = subprocess.run(
                ["file", str(binary)], capture_output=True, text=True, check=True
            ).stdout
            self.assertIn("statically linked", description)
            self.assertIn("stripped", description)

    def test_03b_native_families_match_generator_and_independent_recovery(self) -> None:
        rng = random.Random(0xBA7C)
        words = (HANDOUT_DIR / "dictionary.txt").read_text().splitlines()
        with tempfile.TemporaryDirectory() as directory:
            layout_harness = Path(directory) / "layout_harness"
            fingerprint_harness = Path(directory) / "fingerprint_harness"
            common = [
                "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                "-DTLF_ADMIN_HARNESS",
            ]
            subprocess.run(
                [*common, str(NATIVE_DIR / "record_layout.c"), "-o", str(layout_harness)],
                check=True,
            )
            subprocess.run(
                [*common, str(NATIVE_DIR / "batch_model.c"), "-o", str(fingerprint_harness)],
                check=True,
            )
            for _ in range(128):
                capture = rng.randrange(2)
                tag = rng.randrange(1 << 32)
                count = rng.randrange(5, 25)
                completed = subprocess.run(
                    [str(layout_harness)],
                    input=f"{capture} {tag} {count}\n",
                    text=True,
                    capture_output=True,
                    check=True,
                )
                native_layout = [tuple(map(int, line.split())) for line in completed.stdout.splitlines()]
                generated_layout = generator_record_layout(capture, tag, count)
                self.assertEqual(native_layout, generated_layout)
                self.assertEqual(recovered_layout(capture, tag, count), generated_layout)
                self.assertEqual(recovered_layout_family(tag), layout_family(tag))

                record = rng.randrange(20)
                tokens = rng.sample(words, rng.randrange(1, 4))
                completed = subprocess.run(
                    [str(fingerprint_harness)],
                    input=f"{capture} {tag} {record} {len(tokens)} {' '.join(tokens)}\n",
                    text=True,
                    capture_output=True,
                    check=True,
                )
                native_fingerprint = int(completed.stdout)
                generated_fingerprint = generator_batch_fingerprint(
                    capture, tag, record, tokens
                )
                self.assertEqual(native_fingerprint, generated_fingerprint)
                self.assertEqual(
                    recovered_batch_fingerprint(capture, tag, record, tokens),
                    generated_fingerprint,
                )
                self.assertEqual(
                    recovered_fingerprint_family(capture, tag, record),
                    fingerprint_family(capture, tag, record),
                )
                self.assertLess(generated_fingerprint, FINGERPRINT_MODULUS)

    def test_03c_singleton_fingerprint_is_content_independent(self) -> None:
        dictionary = (HANDOUT_DIR / "dictionary.txt").read_text().splitlines()
        outputs = []
        for token in (dictionary[0], dictionary[17], dictionary[-1]):
            outputs.append(recovered_batch_fingerprint(0, 305419896, 7, [token]))
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(
            generator_batch_fingerprint(0, 305419896, 7, [dictionary[0]]),
            generator_batch_fingerprint(0, 305419896, 7, [dictionary[17]]),
        )

    def test_03d_all_model_families_are_required_by_generated_evidence(self) -> None:
        self.assertEqual(
            {item["layout_family"] for item in self.metadata["sessions"]},
            {0, 1, 2, 3},
        )
        admin_rows = [
            item for item in self.metadata["sessions"] if item["name"] == "admin"
        ]
        used = {
            record["fingerprint_family"]
            for item in admin_rows
            for record in item["layout"]
            if record["count"] > 1
            and set(range(record["start"], record["start"] + record["count"])) & set(range(4, 9))
        }
        self.assertEqual(used, {0, 1, 2, 3})

        by_tag: dict[str, list[dict[str, object]]] = {}
        for item in self.metadata["sessions"]:
            if item["category"] in {"admin", "phrase-decoy"}:
                by_tag.setdefault(item["tag"], []).append(item)
        for tag, rows in by_tag.items():
            graph = {position: set() for position in range(4, 9)}
            covered = set()
            for item in rows:
                for record in item["layout"]:
                    if record["count"] == 1:
                        continue
                    variables = set(
                        range(record["start"], record["start"] + record["count"])
                    ) & set(range(4, 9))
                    covered.update(variables)
                    for source in variables:
                        graph[source].update(variables - {source})
            reached = {4}
            pending = [4]
            while pending:
                current = pending.pop()
                for neighbor in graph[current] - reached:
                    reached.add(neighbor)
                    pending.append(neighbor)
            self.assertEqual(covered, set(range(4, 9)), tag)
            self.assertEqual(reached, set(range(4, 9)), tag)

    def test_03e_official_solver_has_no_native_calculator_calls(self) -> None:
        source = (ROOT / "solution" / "solver" / "solve.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("record_layout", source)
        self.assertNotIn("batch_model", source)

    def test_04_known_sessions_recover_fixed_overhead(self) -> None:
        self.assertEqual(derive_overhead(self.captures), FIXED_OVERHEAD)

    def test_05_both_captures_recover_every_token_length(self) -> None:
        overhead = derive_overhead(self.captures)
        expected: dict[int, list[int]] = {}
        for session in self.metadata["sessions"]:
            expected[int(session["tag"], 0)] = session["token_lengths"]
        for tag in self.captures[0]:
            actual = recover_token_lengths(
                tag, (self.captures[0][tag], self.captures[1][tag]), overhead
            )
            self.assertEqual(actual, expected[tag])

    def test_06_one_capture_is_insufficient_for_admin(self) -> None:
        admin = next(
            item for item in self.metadata["sessions"]
            if item["name"] == "admin" and item["capture"] == 0
        )
        tag = int(admin["tag"], 0)
        for capture_id in (0, 1):
            with self.subTest(capture=capture_id), self.assertRaisesRegex(
                ValueError, "combine both captures"
            ):
                recover_token_lengths(
                    tag,
                    (self.captures[capture_id][tag],),
                    FIXED_OVERHEAD,
                    capture_ids=(capture_id,),
                )

    def test_06b_single_capture_fingerprints_leave_large_phrase_ambiguity(self) -> None:
        admin = next(
            item for item in self.metadata["sessions"]
            if item["name"] == "admin" and item["capture"] == 0
        )
        tag = int(admin["tag"], 0)
        words = (HANDOUT_DIR / "dictionary.txt").read_text(encoding="utf-8").splitlines()
        token_lengths = admin["token_lengths"]
        fixed = {
            0: "the", 1: "recovery", 2: "phrase", 3: "is",
            9: ".", 10: "verify", 11: "now",
        }
        for capture_id in (0, 1):
            flow = self.captures[capture_id][tag]
            candidate_count = 1
            for record_index, ((start, count, _pad), expected) in enumerate(
                zip(recovered_layout(capture_id, tag, 12), flow.fingerprints)
            ):
                positions = tuple(range(start, start + count))
                variables = tuple(position for position in positions if 4 <= position <= 8)
                if not variables:
                    continue
                domains = [
                    [word for word in words if len(word) == token_lengths[position]]
                    for position in variables
                ]
                matches = 0
                for values in product(*domains):
                    assignment = dict(zip(variables, values))
                    tokens = [assignment.get(position, fixed.get(position)) for position in positions]
                    if recovered_batch_fingerprint(capture_id, tag, record_index, tokens) == expected:
                        matches += 1
                self.assertGreater(matches, 0)
                candidate_count *= matches
            self.assertGreaterEqual(candidate_count, 500_000)

    def test_07_phrase_shape_has_many_decoy_flows(self) -> None:
        candidates = candidate_secret_vectors(self.captures, FIXED_OVERHEAD)
        self.assertGreaterEqual(len(candidates), 12)
        self.assertGreaterEqual(len({vector for _tag, vector in candidates}), 10)
        phrases = self._get_phrase_candidates()
        self.assertGreaterEqual(len(phrases), 12)
        self.assertLess(len(phrases), 100_000)

    def test_07b_naive_dictionary_product_is_not_practical(self) -> None:
        words = (HANDOUT_DIR / "dictionary.txt").read_text().splitlines()
        secret_lengths = (5, 7, 6, 8, 9)
        counts = [sum(len(word) == length for word in words) for length in secret_lengths]
        self.assertTrue(all(count >= WORDS_PER_LENGTH for count in counts))
        product = 1
        for count in counts:
            product *= count
        self.assertGreaterEqual(product, WORDS_PER_LENGTH ** 5)

    def test_07c_dictionary_has_no_marked_filler_class_or_rank_pattern(self) -> None:
        words = (HANDOUT_DIR / "dictionary.txt").read_text(encoding="utf-8").splitlines()
        phrase = (PRIVATE_DIR / "recovery_phrase.txt").read_text(encoding="utf-8").split()
        self.assertEqual(tuple(map(len, phrase)), SECRET_LENGTHS)
        candidate_words = [word for word in words if len(word) in SECRET_LENGTHS]
        self.assertTrue(all(word.isascii() and word.islower() and word.isalpha() for word in candidate_words))
        self.assertLess(
            max(
                sum(word.startswith(letter) for word in candidate_words)
                for letter in "abcdefghijklmnopqrstuvwxyz"
            ),
            len(candidate_words) // 8,
        )
        ranks = [
            [word for word in words if len(word) == length].index(secret)
            for length, secret in zip(SECRET_LENGTHS, phrase)
        ]
        self.assertGreaterEqual(len(set(ranks)), 4)
        self.assertFalse(all(right == left + 1 for left, right in zip(ranks, ranks[1:])))

    def test_08_plaintext_and_readme_do_not_leak(self) -> None:
        secret = (PRIVATE_DIR / "flag.txt").read_bytes().strip()
        phrase = (PRIVATE_DIR / "recovery_phrase.txt").read_bytes().strip()
        for path in HANDOUT_DIR.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(secret, data, path.name)
                self.assertNotIn(phrase, data, path.name)
                self.assertNotEqual(path.name, "README.md")

    def test_09_official_solver(self) -> None:
        expected = (PRIVATE_DIR / "flag.txt").read_text(encoding="utf-8").strip()
        with tempfile.TemporaryDirectory(prefix="tlf-public-solver-") as directory:
            copied = Path(directory) / "for_user"
            shutil.copytree(HANDOUT_DIR, copied)
            shutil.copytree(ROOT / "solution", copied / "solution")
            before = {
                str(path.relative_to(copied)): hashlib.sha256(path.read_bytes()).digest()
                for path in copied.rglob("*")
                if path.is_file()
            }
            environment = os.environ.copy()
            environment.pop("TLF_HANDOUT_DIR", None)
            completed = subprocess.run(
                ["python3", "solution/solver/solve.py"],
                cwd=copied,
                env=environment,
                text=True,
                capture_output=True,
                timeout=600,
                check=True,
            )
            output_lines = [
                line.strip()
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            self.assertTrue(output_lines, completed.stderr)
            actual = output_lines[-1]
            after = {
                str(path.relative_to(copied)): hashlib.sha256(path.read_bytes()).digest()
                for path in copied.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
        self.assertEqual(actual, expected)
        self.assertTrue(actual.startswith("SHA{"))
        self.assertEqual(
            hashlib.sha256(actual.encode()).hexdigest(),
            hashlib.sha256(expected.encode()).hexdigest(),
        )

    def test_10_manifest_discloses_complete_flag_seal(self) -> None:
        manifest = json.loads((HANDOUT_DIR / "capture_manifest.json").read_text(encoding="utf-8"))
        serialized = json.dumps(manifest)
        self.assertNotIn("layout_tool", serialized)
        self.assertNotIn("model_tool", serialized)
        self.assertIn("self-test only", manifest["native_models"]["interface"])
        self.assertEqual(
            manifest["target_message_shape"],
            "the recovery phrase is <dictionary word 1> <dictionary word 2> "
            "<dictionary word 3> <dictionary word 4> <dictionary word 5> . verify now",
        )
        seal = manifest["flag_seal"]
        self.assertEqual(seal["aead"], "AES-256-GCM")
        self.assertEqual(seal["aad_ascii"], "stream-token-length-v2")
        self.assertEqual(seal["key_domain_ascii"], "token-length-v2")
        self.assertTrue(seal["key_domain_has_trailing_nul"])
        self.assertIn("recovery_phrase UTF-8", seal["key"])

    def test_11_handout_contains_only_release_files(self) -> None:
        expected = {
            "batch_model", "capture_a.pcap", "capture_b.pcap",
            "capture_manifest.json", "dictionary.txt", "flag.enc",
            "known_sessions.txt", "record_layout",
        }
        actual = {
            str(path.relative_to(HANDOUT_DIR))
            for path in HANDOUT_DIR.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
