from __future__ import annotations

import binascii
import contextlib
import io
import math
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HANDOUT = ROOT / ".build" / "for_user"
os.environ["VAULT_HANDOUT_DIR"] = str(HANDOUT)
sys.path.insert(0, str(ROOT.parent / "for_user"))

from app.core import VaultOracle, layout_state as server_layout_state
from build_assets import main as build_assets
from solution.solver.solve import (
    infer_oracle_parameters,
    load_public_schema,
    layout_state,
    solve,
)

SOLVER_SOURCE = ROOT / "solution" / "solver" / "solve.py"


@contextlib.contextmanager
def environment(**changes: str | None):
    previous = {name: os.environ.get(name) for name in changes}
    try:
        for name, value in changes.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class LocalTransport:
    def __init__(self):
        self.oracle = VaultOracle()
        self.note = ""
        self.counter = 0
        self.requests = 0

    def share(self, value: str) -> None:
        self.note = value

    def export(self, seed: int, style: int, filler: int) -> int:
        result = self.oracle.export_size(self.note, self.counter, seed, style, filler)
        self.counter += 1
        self.requests += 1
        return int(result["size"])


class BatchLocalTransport(LocalTransport):
    def __init__(self):
        super().__init__()
        self.http_requests = 0

    def measure(self, value: str, exports: list[tuple[int, int, int]]) -> list[int]:
        self.http_requests += 1
        return self.measure_batch([(value, exports)])[0]

    def measure_batch(
        self, groups: list[tuple[str, list[tuple[int, int, int]]]]
    ) -> list[list[int]]:
        self.http_requests += 1
        results: list[list[int]] = []
        for note, exports in groups:
            sizes: list[int] = []
            for seed, style, filler in exports:
                result = self.oracle.export_size(
                    note, self.counter, seed, style, filler, b"batch-test-team"
                )
                sizes.append(int(result["size"]))
                self.counter += 1
                self.requests += 1
            self.note = note
            results.append(sizes)
        return results


def quiet_solve() -> tuple[str, int]:
    with contextlib.redirect_stdout(io.StringIO()):
        return solve(LocalTransport())


def quiet_batch_solve() -> tuple[str, int, int]:
    transport = BatchLocalTransport()
    with contextlib.redirect_stdout(io.StringIO()):
        flag, requests = solve(transport)
    return flag, requests, transport.http_requests


def main() -> None:
    build_assets()
    print("[1/9] 공개 지급본 구조·schema 검사")
    expected_files = {"api_examples.json", "layoutgen", "schema.wasm"}
    actual_files = {
        str(path.relative_to(HANDOUT))
        for path in HANDOUT.rglob("*")
        if path.is_file()
    }
    assert actual_files == expected_files
    schema = load_public_schema()
    assert set(schema) == {"format", "payload_alphabet", "payload_length", "crc", "calibration"}
    assert schema["format"] == "SHA{<payload>-<crc16>}"
    assert schema["payload_alphabet"] == "0123456789abcdef"
    inferred_layout, inferred_bucket, inferred_epoch = infer_oracle_parameters(schema)
    assert (inferred_layout, inferred_bucket, inferred_epoch) == (2, 16, 16)
    observations = schema["calibration"]["observations"]
    assert len(observations) == 64
    sizes = [int(item["size"]) for item in observations]
    assert len(set(sizes)) > 1
    assert len({sum(sizes[start:start + 16]) for start in range(0, 64, 16)}) == 1
    assert (HANDOUT / "schema.wasm").read_bytes().startswith(b"\x00asm")
    schema_bytes = (HANDOUT / "schema.wasm").read_bytes()
    for answer_sheet_marker in (
        b"VCFG", b"canonical_layout", b"bucket_size", b"stable_score",
        b"probe_prefix", b"secret permutation", b"fixed Huffman", b"sorted compact JSON",
    ):
        assert answer_sheet_marker not in schema_bytes

    print("[2/9] 비계산기 layoutgen·4-family 모델 동치 검사")
    binary = HANDOUT / "layoutgen"
    description = subprocess.run(
        ["file", str(binary)], text=True, capture_output=True, check=True
    ).stdout
    assert "statically linked" in description and "stripped" in description
    observations_from_binary = []
    for supplied in (b"", b"0 0 0\n", b"37 18841 2\n", b"garbage\n"):
        completed = subprocess.run([str(binary)], input=supplied, capture_output=True)
        observations_from_binary.append(
            (completed.returncode, completed.stdout, completed.stderr)
        )
    assert len(set(observations_from_binary)) == 1
    assert observations_from_binary[0] == (0, b"layout model self-test: ok\n", b"")
    assert b"layout=" not in binary.read_bytes() and b"cover=" not in binary.read_bytes()

    constants = [0x6D2B79F5, 0xA511E9B3, 0x9E3779B9, 0xC0DEC0DE]
    with tempfile.TemporaryDirectory() as directory:
        harness = Path(directory) / "layout_harness"
        subprocess.run([
            "gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            "-DVAULT_ADMIN_HARNESS", str(ROOT / "native" / "layoutgen.c"),
            "-o", str(harness),
        ], check=True)
        rng = random.Random(0x1A70)
        families = set()
        for _ in range(256):
            counter = rng.randrange(1 << 20)
            seed = rng.randrange(1 << 32)
            style = rng.randrange(4)
            families.add((style + ((counter >> 4) & 3)) & 3)
            completed = subprocess.run(
                [str(harness)], input=f"{counter} {seed} {style}\n",
                text=True, capture_output=True, check=True,
            )
            native = tuple(map(int, completed.stdout.split()))
            expected = server_layout_state(counter, seed, style, constants)
            assert native == expected == layout_state(counter, seed, style)
        assert families == {0, 1, 2, 3}

    print("[2b/9] 팀별 비밀 permutation padding·16회 합산 불변성 검사")
    oracle = VaultOracle()
    first = [oracle.padding_noise(counter, b"team-alpha") for counter in range(16)]
    second = [oracle.padding_noise(counter, b"team-beta") for counter in range(16)]
    next_epoch = [oracle.padding_noise(16 + counter, b"team-alpha") for counter in range(16)]
    assert sorted(first) == sorted(second) == sorted(next_epoch) == list(range(16))
    assert first != second and first != next_epoch
    note = "recovery=SHA{a1b2"
    compressed = oracle._compress(oracle._serialize(note, 2))
    exact_without_padding = len(compressed) + 12 + 16
    expected_sum = sum(
        math.ceil((exact_without_padding + filler) / 16) * 16
        for filler in range(16)
    )
    measured_sum = 0
    for counter in range(16):
        seed = next(
            candidate for candidate in range(4096)
            if layout_state(counter, candidate, 0) == (2, 0)
        )
        measured_sum += oracle.export_size(
            note, counter, seed, 0, 0, b"team-alpha"
        )["size"]
    assert measured_sum == expected_sum

    old_binary_successes = 0
    for epoch in range(64):
        counter = epoch * 16
        seed = next(candidate for candidate in range(4096) if layout_state(counter, candidate, 0) == (2, 0))
        baseline = oracle.export_size(note, counter, seed, 0, 0, b"binary-regression")["size"]
        low, high = 1, 15
        query_offset = 1
        while low < high:
            middle = (low + high) // 2
            current_counter = counter + query_offset
            query_offset += 1
            seed = next(
                candidate for candidate in range(4096)
                if layout_state(current_counter, candidate, 0) == (2, 0)
            )
            measured = oracle.export_size(
                note, current_counter, seed, 0, middle, b"binary-regression"
            )["size"]
            if measured > baseline:
                high = middle
            else:
                low = middle + 1
        estimated = baseline - low + 1
        old_binary_successes += estimated == exact_without_padding
    assert old_binary_successes <= 8
    print(f"  기존 5요청 경계 역산 성공: {old_binary_successes}/64 epoch")

    print("[2c/9] subset/group-testing·반복 증폭 언인텐 회귀")
    alphabet = "0123456789abcdef"
    payload = str(oracle.config["payload"])

    def stable_group_score(candidate_note: str) -> int:
        reference = VaultOracle()
        total = 0
        for counter in range(16):
            seed = next(
                candidate for candidate in range(32)
                if layout_state(counter, candidate, 0) == (2, 0)
            )
            total += reference.export_size(
                candidate_note, counter, seed, 0, 0, b"group-regression"
            )["size"]
        return total

    templates = (
        lambda prefix, chars: "|".join(f"recovery=SHA{{{prefix}{char}" for char in chars),
        lambda prefix, chars: "|".join(f"SHA{{{prefix}{char}" for char in chars),
        lambda prefix, chars: "|".join(f"{prefix}{char}" for char in chars),
    )
    for template in templates:
        decisive = successful = 0
        for depth, wanted in enumerate(payload):
            scores = [
                stable_group_score(template(payload[:depth], alphabet[:8])),
                stable_group_score(template(payload[:depth], alphabet[8:])),
            ]
            if scores[0] != scores[1]:
                decisive += 1
                expected_half = 0 if wanted in alphabet[:8] else 1
                successful += scores.index(min(scores)) == expected_half
        assert decisive <= 4 and successful <= 4

    for depth in range(len(payload)):
        prefix = payload[:depth]
        for repetitions in (1, 2, 4, 8, 16):
            exact_sizes = []
            for character in alphabet:
                note = "|".join(
                    [f"recovery=SHA{{{prefix}{character}"] * repetitions
                )
                exact_sizes.append(len(oracle._compress(oracle._serialize(note, 2))))
            assert max(exact_sizes) - min(exact_sizes) <= 2

    print("[3/9] 기본 인스턴스 공식 풀이 검사")
    with environment(FLAG=None, REQUIRE_RUNTIME_FLAG=None):
        flag, requests = quiet_solve()
        expected = str(VaultOracle().config["flag"])
    assert flag == expected
    assert requests == 6928
    batch_flag, batch_requests, http_requests = quiet_batch_solve()
    assert batch_flag == expected
    assert batch_requests == requests
    assert http_requests <= 30

    print("[4/9] 다양한 유효 플래그 64개 안정성·예산 회귀 검사")
    rng = random.Random(0xA11D17)
    request_counts = []
    for _ in range(64):
        payload = "".join(rng.choice("0123456789abcdef") for _ in range(12))
        crc = binascii.crc_hqx(payload.encode(), 0xFFFF)
        expected_flag = f"SHA{{{payload}-{crc:04x}}}"
        with environment(FLAG=expected_flag, REQUIRE_RUNTIME_FLAG="1"):
            recovered, used = quiet_solve()
        assert recovered == expected_flag
        assert used <= 16000
        request_counts.append(used)

    print("[5/9] 운영 플래그 fail-closed·설정 검증")
    with environment(FLAG=None, REQUIRE_RUNTIME_FLAG="1"):
        try:
            VaultOracle()
        except ValueError as error:
            assert "설정되지 않았습니다" in str(error)
        else:
            raise AssertionError("missing production FLAG was accepted")
    for invalid in ("", "BAD{x}", "SHA{ABCDEF123456-0000}", "SHA{123-0000}"):
        with environment(FLAG=invalid, REQUIRE_RUNTIME_FLAG="1"):
            try:
                VaultOracle()
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid FLAG was accepted: {invalid!r}")
    with environment(PADDING_SECRET=None, REQUIRE_RUNTIME_PADDING="1"):
        try:
            VaultOracle()
        except ValueError as error:
            assert "PADDING_SECRET" in str(error)
        else:
            raise AssertionError("missing production PADDING_SECRET was accepted")
    for invalid in ("", "00", "zz" * 32, "00" * 31):
        with environment(PADDING_SECRET=invalid, REQUIRE_RUNTIME_PADDING="1"):
            try:
                VaultOracle()
            except ValueError:
                pass
            else:
                raise AssertionError("invalid PADDING_SECRET was accepted")

    print("[6/9] 90팀 배포 비밀·deployment namespace 생성 검사")
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        completed = subprocess.run(
            [
                sys.executable, str(ROOT / "prepare_deployment.py"),
                "--teams", "90", "--secret-dir", str(temp / "secrets"),
                "--workspace-env", str(temp / "workspace.env"),
            ],
            text=True, capture_output=True, check=True,
        )
        assert "SHA{" not in completed.stdout
        deployment = temp / "secrets" / "deployment.env"
        tokens = temp / "secrets" / "team_tokens.csv"
        assert stat.S_IMODE((temp / "secrets").stat().st_mode) == 0o700
        assert stat.S_IMODE(deployment.stat().st_mode) == 0o600
        assert stat.S_IMODE(tokens.stat().st_mode) == 0o600
        values = dict(
            line.split("=", 1)
            for line in deployment.read_text(encoding="utf-8").splitlines()
            if line
        )
        assert re.fullmatch(r"[0-9a-f]{32}", values["DEPLOYMENT_ID"])
        assert re.fullmatch(r"SHA\{[0-9a-f]{12}-[0-9a-f]{4}\}", values["FLAG"])
        assert values["FLAG"] == expected
        assert re.fullmatch(r"[0-9a-f]{64}", values["PADDING_SECRET"])
        team_tokens = values["TEAM_TOKENS"].split(",")
        assert len(team_tokens) == len(set(team_tokens)) == 90
        assert all(re.fullmatch(r"[0-9a-f]{48}", token) for token in team_tokens)
        workspace_values = dict(
            line.split("=", 1)
            for line in (temp / "workspace.env").read_text(encoding="utf-8").splitlines()
            if line
        )
        assert workspace_values["VAULT_EXAMPLE_TEAM_TOKEN"] == team_tokens[0]

    print("[7/9] 공식 풀이의 지급본 독립성·손상 schema 거부 검사")
    source = SOLVER_SOURCE.read_text(encoding="utf-8")
    assert "from app" not in source and "import app" not in source
    assert "layoutgen" not in source and "subprocess" not in source
    assert "canonical_layout" not in source and "stable_score" not in source
    with tempfile.TemporaryDirectory() as directory:
        copied = Path(directory) / "for_user"
        shutil.copytree(HANDOUT, copied)
        shutil.copytree(ROOT / "solution", copied / "solution")
        copied_environment = os.environ.copy()
        copied_environment.pop("VAULT_HANDOUT_DIR", None)
        copied_environment.pop("PYTHONPATH", None)
        copied_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        copied_solver = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from solution.solver.solve import load_public_schema, "
                    "infer_oracle_parameters; "
                    "schema=load_public_schema(); "
                    "assert infer_oracle_parameters(schema)==(2,16,16)"
                ),
            ],
            cwd=copied,
            env=copied_environment,
            text=True,
            capture_output=True,
        )
        assert copied_solver.returncode == 0, copied_solver.stderr
        with environment(VAULT_HANDOUT_DIR=str(copied)):
            assert load_public_schema() == schema
            (copied / "schema.wasm").write_bytes(b"\x00asm\x01\x00")
            try:
                load_public_schema()
            except RuntimeError:
                pass
            else:
                raise AssertionError("truncated schema.wasm was accepted")

    print("[8/9] 평문 플래그·개발 payload 누출 검사")
    secret = expected.encode()
    payload = str(VaultOracle().config["payload"]).encode()
    for path in HANDOUT.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert secret not in data, path.name
            assert payload not in data, path.name

    print("[9/9] API·배포 fail-closed 설정 정적 검사")
    main_source = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'os.environ.get("TEAM_TOKENS", "")' in main_source
    assert "team_tokens_not_configured" in main_source
    assert "MAX_REQUEST_BODY = 32768" in main_source
    assert '@app.post("/api/measure-batch")' in main_source
    assert 'REQUIRE_RUNTIME_FLAG: "1"' in compose
    assert 'REQUIRE_RUNTIME_PADDING: "1"' in compose
    assert "CTFD_BASE_URL:" in compose
    assert "vault-boundary-example-token" not in compose
    assert "DEPLOYMENT_ID" in (ROOT / "app" / "store.py").read_text(encoding="utf-8").upper()

    print(
        "전체 통과: 정적 인스턴스 6928회, 형식 회귀 64개 "
        f"min={min(request_counts)} max={max(request_counts)}"
    )


if __name__ == "__main__":
    main()
