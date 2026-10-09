from __future__ import annotations

import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HANDOUT = ROOT / ".build" / "for_user"
os.environ["BTG_HANDOUT_DIR"] = str(HANDOUT)
sys.path.insert(0, str(ROOT.parent / "for_user"))

from build_assets import main as build_assets
from challenge.core import (
    ChallengeService,
    PROFILES,
    TeamStore,
    pack_shingle,
    route_profiles,
    template_index,
)
from solution.solver.common import GraphSolver, LocalTransport


def safe_seed(counter: int, constants: list[int], style: int = 0) -> int:
    return next(seed for seed in range(4096) if template_index(seed, counter, style, constants) == 0)


def main() -> None:
    build_assets()
    print("[1/8] 실제 WASM tokenizer differential 검사")
    service = ChallengeService(":memory:")
    rng = random.Random(0xD1FF2026)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 {}_:%.-!/"
    samples = [
        "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 120)))
        for _ in range(1000)
    ]
    node = shutil.which("node")
    if node is None:
        candidates = sorted(Path.home().glob(".config/nvm/versions/node/*/bin/node"))
        node = str(candidates[-1]) if candidates else None
    if node is None:
        raise RuntimeError("Node.js is required for the WASM differential test")
    completed = subprocess.run(
        [node, str(ROOT / "solution/wasm_probe.js"), str(HANDOUT / "normalizer.wasm")],
        input=json.dumps(samples),
        text=True,
        capture_output=True,
        check=True,
    )
    actual = json.loads(completed.stdout)
    expected = [service.tokenizer.tokenize(sample) for sample in samples]
    assert actual == expected

    print("[2/8] 단일-window 강제 및 그룹 질의 회귀 검사")
    token = "regression-team-token"
    session_info = service.new_session(token)
    session = str(session_info["session"])
    team_id = service.team_identity(token)
    state = service.store.get_or_assign(team_id)
    document = service.instances[state.instance_index]["documents"][0]
    shingle_ids = [int(value) for value in document[:5]]
    shingle = [service.vocab[value] for value in shingle_ids]
    profile_index = route_profiles(pack_shingle(shingle_ids))[0]
    seed = safe_seed(0, service.style_constants)
    single = service.generate(session, PROFILES[profile_index], " ".join(shingle), seed, 0)
    assert single["status"] == "blocked"
    seed = safe_seed(1, service.style_constants)
    grouped = service.generate(session, PROFILES[profile_index], " ".join(shingle + shingle), seed, 0)
    assert grouped["status"] == "allowed"

    print("[3/8] 재접속 상태·예산 영속 검사")
    resumed = service.new_session(token)
    assert resumed["session"] == session
    assert resumed["counter"] == 2 and resumed["remaining"] == 1998
    budget_token = "budget-regression-team"
    budget_session = str(service.new_session(budget_token)["session"])
    for counter in range(service.budget):
        seed = safe_seed(counter, service.style_constants)
        service.generate(budget_session, "A", "one", seed, 0)
    exhausted = service.new_session(budget_token)
    assert exhausted["counter"] == service.budget and exhausted["remaining"] == 0
    try:
        service.generate(budget_session, "A", "one", 0, 0)
        raise AssertionError("new session reset the team budget")
    except ValueError:
        pass

    validation_token = "validation-before-consume"
    validation_session = str(service.new_session(validation_token)["session"])
    try:
        service.generate(validation_session, "A", "one", 0, 99)
        raise AssertionError("invalid style accepted")
    except ValueError:
        pass
    assert service.new_session(validation_token)["counter"] == 0

    other_token = "session-owner-other"
    try:
        service.require_session_owner(validation_session, other_token)
        raise AssertionError("cross-team session accepted")
    except ValueError:
        pass

    concurrent_token = "concurrent-counter-regression-team"
    concurrent_session = str(service.new_session(concurrent_token)["session"])

    def concurrent_generate(_index: int) -> int:
        result = service.generate(concurrent_session, "A", "one", 0, 0)
        return int(result["counter"])

    with ThreadPoolExecutor(max_workers=32) as executor:
        concurrent_counters = list(executor.map(concurrent_generate, range(200)))
    assert sorted(concurrent_counters) == list(range(200))
    concurrent_state = service.new_session(concurrent_token)
    assert concurrent_state["counter"] == 200
    assert concurrent_state["remaining"] == service.budget - 200

    claim_token = "claim-coverage-regression-team"
    claim_session = str(service.new_session(claim_token)["session"])
    claim_team_id = service.team_identity(claim_token)
    claim_state = service.store.get_or_assign(claim_team_id)
    correct_payload = "".join(service.instances[claim_state.instance_index]["payload"])
    early_claim = service.claim(claim_session, correct_payload)
    assert early_claim["status"] == "incomplete"
    assert "flag" not in early_claim
    assert early_claim["next_counter"] == 1 and early_claim["remaining"] == service.budget - 1
    assert early_claim["coverage"] < early_claim["coverage_required"]
    rejected_probe = service.claim(claim_session, "aa" * 18)
    assert rejected_probe["status"] == "incomplete"
    assert rejected_probe.keys() == early_claim.keys()
    claim_resumed = service.new_session(claim_token)
    assert claim_resumed["counter"] == 2 and claim_resumed["remaining"] == service.budget - 2

    print("[4/8] fail-closed 인증과 배포 namespace 격리 검사")
    denied = subprocess.run(
        [sys.executable, "-c", "import challenge.server"],
        cwd=Path(__file__).resolve().parent,
        env={**os.environ, "TEAM_TOKENS": ""},
        text=True,
        capture_output=True,
    )
    assert denied.returncode != 0 and "allowlist" in denied.stderr
    with tempfile.TemporaryDirectory(prefix="bloom-store-audit-") as directory:
        database = Path(directory) / "state.sqlite3"
        first_store = TeamStore(database, 1, 10, "deployment-alpha")
        second_store = TeamStore(database, 1, 10, "deployment-beta")
        first_store.get_or_assign("a" * 64)
        second_store.get_or_assign("b" * 64)
        first_store.db.close()
        second_store.db.close()

    print("[5/8] profile density·오탐률 균형 검사")
    densities = [item.density for item in service._filters(0)]
    assert max(densities) - min(densities) < 0.003
    rates = [service.measured_false_positive_rate(0, index, 10_000) for index in range(3)]
    assert max(rates) - min(rates) < 0.008
    print(f"  density={densities} fpr={rates}")

    print("[6/8] 전체 128개 팀별 seed 공식 풀이 및 2,000회 상한 검사")
    validation_service = ChallengeService(":memory:")
    counts: list[int] = []
    assigned: set[int] = set()
    for index in range(len(validation_service.instances)):
        team_token = f"seed-validation-team-{index:03d}"
        identity = validation_service.team_identity(team_token)
        assigned.add(validation_service.store.get_or_assign(identity).instance_index)
        transport = LocalTransport(validation_service, team_token)
        result = GraphSolver(transport, verbose=False).solve()
        assert result.flag == validation_service.scoreboard_flag
        assert result.flag.startswith("SHA{")
        assert result.requests <= validation_service.budget
        state = validation_service.store.get_or_assign(identity)
        coverage = validation_service.coverage_progress(identity, state.instance_index)
        assert coverage[0] == coverage[1]
        assert state.counter == result.requests
        counts.append(result.requests)
    assert len(assigned) == len(validation_service.instances)
    ordered = sorted(counts)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    print(
        f"  min={min(counts)} median={statistics.median(counts)} "
        f"p95={p95} max={max(counts)}"
    )

    print("[7/8] 팀별 payload와 instance 고정성 검사")
    first = service.new_session("assignment-team-alpha")
    second = service.new_session("assignment-team-alpha")
    other = service.new_session("assignment-team-beta")
    assert first["instance"] == second["instance"]
    assert first["instance"] != other["instance"]

    print("[8/8] 지급 파일 비밀·풀이기 누출 검사")
    secret = service.scoreboard_flag.encode()
    expected_release = {
        "challenge.json", "examples.json", "generator", "normalizer.wasm", "vocab.txt"
    }
    actual_release: set[str] = set()
    for path in HANDOUT.rglob("*"):
        if path.is_file():
            actual_release.add(str(path.relative_to(HANDOUT)))
            data = path.read_bytes()
            assert secret not in data, path
            assert path.name != "solve_optimized.py"
    assert actual_release == expected_release
    solver_source = (ROOT / "solution/solver/common.py").read_text(encoding="utf-8")
    assert "from challenge" not in solver_source and "import challenge" not in solver_source
    with tempfile.TemporaryDirectory(prefix="bloom-public-solver-") as directory:
        copied = Path(directory) / "for_user"
        shutil.copytree(HANDOUT, copied)
        shutil.copytree(ROOT / "solution", copied / "solution")
        copied_environment = os.environ.copy()
        copied_environment.pop("BTG_HANDOUT_DIR", None)
        copied_environment.pop("PYTHONPATH", None)
        copied_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        imported = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from solution.solver.common import recover_token_ids, "
                    "pack_shingle, route_profiles, template_index; "
                    "ids=recover_token_ids(['sha','{','v3','_','}']); "
                    "assert len(ids)==5; "
                    "assert len(route_profiles(pack_shingle(tuple(ids.values()))))==2; "
                    "assert 0<=template_index(0,0,0)<8"
                ),
            ],
            cwd=copied,
            env=copied_environment,
            text=True,
            capture_output=True,
        )
        assert imported.returncode == 0, imported.stderr
    print("전체 통과")


if __name__ == "__main__":
    main()
