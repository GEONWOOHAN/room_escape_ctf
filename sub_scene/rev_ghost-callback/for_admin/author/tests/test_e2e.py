#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import hashlib
import inspect
import itertools
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
HANDOUT = ROOT / ".build" / "for_user"
os.environ["GHOST_HANDOUT_DIR"] = str(HANDOUT)
sys.path[:0] = [
    str(ROOT / "author/vendor"), str(ROOT / "author"), str(ROOT / "author/generator"),
    str(ROOT / "solution/solver"), str(ROOT / "author/package_builder"), str(HANDOUT),
]
import generate
import solve
from common_crypto import aead_decrypt
from package_format import make_package, make_tar, split_package


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def updater_ok():
    return subprocess.run([str(HANDOUT / "updater")], cwd=HANDOUT, capture_output=True).returncode == 0


def write_package(entries, mutate_manifest=None):
    manifest, signature, _payload = split_package((HANDOUT / "normal_update.pkg").read_bytes())
    if mutate_manifest:
        manifest = mutate_manifest(manifest)
    (HANDOUT / "candidate.pkg").write_bytes(make_package(manifest, signature, make_tar(entries)))


def main():
    print("[1/13] regenerate fleet and accept vendor package", flush=True)
    generate.main()
    require(updater_ok(), "vendor package rejected")
    normal = (HANDOUT / "normal_update.pkg").read_bytes()
    manifest, _signature, payload = split_package(normal)
    entries = solve.original_entries(payload)

    print("[2/13] official three-device solve", flush=True)
    plaintext, chains, events = solve.solve_workspace(progress=False)
    require(plaintext.encode() == generate.FLAG, "official flag mismatch")
    player_decrypt = subprocess.run(
        [sys.executable, str(HANDOUT / "decrypt_flag.py")],
        cwd=HANDOUT,
        text=True,
        capture_output=True,
    )
    require(
        player_decrypt.returncode == 0 and player_decrypt.stdout.strip() == plaintext,
        f"player decryptor mismatch: {player_decrypt.stderr.strip()}",
    )
    require(all(len(chains[name]) == solve.CHAIN_LENGTH for name in solve.DEVICE_NAMES), "chain depth mismatch")
    outputs = solve.parse_outputs((HANDOUT / "callback_outputs.bin").read_bytes())
    require(all(
        len(outputs[name]) == solve.EXPECTED_TRANSCRIPT for name in solve.DEVICE_NAMES
    ), "transcript length mismatch")
    good_candidate = (HANDOUT / "candidate.pkg").read_bytes()
    good_receipt = (HANDOUT / ".stage/.install_receipt").read_bytes()

    print("[3/13] route proof derives every calibration seed byte", flush=True)
    calibration_data = (HANDOUT / ".stage/profiles/calibration.bin").read_bytes()
    recovered = {}
    for name in solve.DEVICE_NAMES:
        firmware = (HANDOUT / f"firmware_{name}.bin").read_bytes()
        edges = solve.recover_callback_graph(firmware)
        route_target, chain = solve.recover_route_target(
            firmware, solve.recover_layers(edges)
        )
        recovered[name] = {"edges": edges, "route_target": route_target, "chain": chain}
    mmio_seed, permutation_seed = solve.calibration_seeds(recovered)
    require(calibration_data[8:24] == mmio_seed, "MMIO seed is not route-derived")
    require(calibration_data[24:40] == permutation_seed, "permutation seed is not route-derived")
    solver_source = (ROOT / "solution/solver/solve.py").read_text(encoding="utf-8")
    require("c001d00d" not in solver_source and "bytes(range(16))" not in solver_source,
            "official solver still contains private calibration constants")
    public_spec = json.loads((HANDOUT / "device.json").read_text(encoding="utf-8"))
    require(public_spec["calibration_derivation"]["domain_hex"] == solve.CALIBRATION_KDF_DOMAIN.hex(),
            "public calibration derivation spec drift")

    print("[4/13] signature and all required objects remain immutable", flush=True)
    write_package(entries, lambda value: value[:-1] + bytes([value[-1] ^ 1]))
    require(not updater_ok(), "tampered manifest accepted")
    for target in ("firmware/firmware_a.bin", "firmware/firmware_b.bin",
                   "firmware/firmware_c.bin", "profiles/calibration.bin"):
        changed = []
        for path, data in entries:
            if path == target:
                data = bytes([data[0] ^ 1]) + data[1:]
            changed.append((path, data))
        write_package(changed)
        require(not updater_ok(), f"tampered required object accepted: {target}")

    print("[5/13] traversal blocked; NFKC-equivalent paths share one semantic receipt", flush=True)
    write_package(entries + [("extras/%2e%2e/profiles/calibration.bin", b"X" * 64)])
    require(not updater_ok(), "plain percent-dot traversal accepted")
    write_package(entries + [("extras/../../outside.bin", b"blocked")])
    require(not updater_ok(), "literal traversal accepted")
    (HANDOUT / "candidate.pkg").write_bytes(good_candidate)
    require(updater_ok(), "intended compatibility-character rebinding rejected")
    require((HANDOUT / ".stage/.install_receipt").read_bytes() == good_receipt,
            "canonical exploit semantic receipt drift")
    compatibility_dots = ("\u2024", "\ufe52", "\uff0e")
    for first, second in itertools.product(compatibility_dots, repeat=2):
        encoded = quote(first + second, safe="")
        for spelling in (encoded, encoded.lower()):
            path = f"extras/{spelling}/profiles/calibration.bin"
            write_package(entries + [(path, calibration_data)])
            require(updater_ok(), f"equivalent NFKC path rejected: {path}")
            require(
                (HANDOUT / ".stage/.install_receipt").read_bytes() == good_receipt,
                f"equivalent path changed semantic receipt: {path}",
            )
    (HANDOUT / "candidate.pkg").write_bytes(good_candidate)
    require(updater_ok(), "canonical candidate restore failed")

    print("[6/13] event parser bounds and clean calibration behavior", flush=True)
    runner = solve.load_runner()
    invalid_path = HANDOUT / "invalid-events.json"
    invalid_path.write_text(json.dumps({"events": [
        {"cycle": 1, "channel": solve.CALLBACK_COUNT, "sample": 0, "status": 1}
    ]}))
    try:
        try:
            runner.read_events(invalid_path)
            raise AssertionError("out-of-range channel accepted")
        except ValueError:
            pass
    finally:
        invalid_path.unlink(missing_ok=True)
    normal_cal = dict(entries)["profiles/calibration.bin"]
    benign_events = {"events": [
        {"cycle": 1200, "channel": 1, "sample": 84, "status": 0}
    ]}
    for name in solve.DEVICE_NAMES:
        empty = runner.run_firmware(
            (HANDOUT / f"firmware_{name}.bin").read_bytes(), normal_cal, benign_events["events"]
        )
        require(empty == b"", f"device_{name}: clean calibration executed callbacks")

    print("[7/13] six callback families, decoy tables and coupled 4^20 search", flush=True)
    actual_table_addresses = []
    for name, seed in zip(solve.DEVICE_NAMES, generate.BUILD_SEEDS):
        firmware = (HANDOUT / f"firmware_{name}.bin").read_bytes()
        rebuilt, metadata = generate.build(seed, expected_nonce=generate.COMMON_NONCE)
        require(rebuilt == firmware, "deterministic firmware rebuild drift")
        families = {item["codegen_family"] for item in metadata["callbacks"]}
        require(families == set(range(6)), f"device_{name}: missing codegen family {families}")
        table_candidates = solve.pointer_table_candidates(firmware)
        require(len(table_candidates) == 3, f"device_{name}: decoy pointer tables missing")
        addresses = solve.recover_pointer_table(firmware)
        actual_address = next(address for address, values in table_candidates if values == addresses)
        actual_table_addresses.append(actual_address)
        require(actual_address == metadata["addresses"]["callback_pointers"], "ISR table selection drift")
        require(
            len(addresses) == solve.CALLBACK_COUNT
            and len(set(addresses)) == solve.CALLBACK_COUNT,
            "pointer table invalid",
        )
        ordered = sorted(addresses)
        gaps = {right - left for left, right in zip(ordered, ordered[1:])}
        require(len(gaps) >= 8, "callback placement still has a fixed stride")
        legacy_complete = sum(
            len(solve.masked_constants(solve.callback_instructions(firmware, address))) >= 10
            for address in addresses
        )
        require(0 < legacy_complete < solve.CALLBACK_COUNT // 3,
                f"legacy masked parser unexpectedly covers {legacy_complete} callbacks")
        edges = solve.recover_callback_graph(firmware)
        layers = solve.recover_layers(edges)
        target, recovered_chain = solve.recover_route_target(firmware, layers)
        require(
            len(layers) == solve.CHAIN_LENGTH and all(len(layer) == 4 for layer in layers),
            "branch graph drift",
        )
        require(recovered_chain == chains[name], "MITM route is not unique")
        state = (0, 0)
        by_id = {edge[0]: edge for edge in edges}
        for callback_id in chains[name]:
            edge = by_id[callback_id]
            choice = (edge[0], edge[2], edge[3], edge[4], edge[5], edge[6])
            next_state = solve.route_forward(state, choice)
            require(solve.route_inverse(next_state, choice) == state, "route transition not invertible")
            state = next_state
        require(state == tuple(target), "coupled terminal state mismatch")
    require(len(set(actual_table_addresses)) >= 2, "fleet reuses one callback table slot")
    require(4 ** solve.CHAIN_LENGTH == 1_099_511_627_776, "declared path space drift")

    print("[8/13] one wrong semantic choice breaks AEAD", flush=True)
    firmwares = {name: (HANDOUT / f"firmware_{name}.bin").read_bytes() for name in solve.DEVICE_NAMES}
    wrong_outputs = dict(outputs)
    edges = solve.recover_callback_graph(firmwares["a"])
    layers = solve.recover_layers(edges)
    wrong_chain = chains["a"].copy()
    wrong_chain[5] = next(item[0] for item in layers[5] if item[0] != wrong_chain[5])
    _nonce, targets = solve.recover_nonce_and_targets(firmwares["a"])
    wrong_schedule = solve.build_events(
        wrong_chain, mmio_seed, permutation_seed, targets
    )
    wrong_outputs["a"] = runner.run_firmware(
        firmwares["a"], calibration_data, wrong_schedule
    )
    blob = (HANDOUT / "flag.enc").read_bytes()
    try:
        aead_decrypt(
            solve.derive_key(calibration_data, firmwares, wrong_outputs),
            blob[4:16], blob[16:], solve.AAD,
        )
        raise AssertionError("wrong route passed authentication")
    except ValueError:
        pass

    print("[9/13] random transcripts never authenticate", flush=True)
    random_source = random.Random(20260911)
    for _ in range(64):
        fake_outputs = {
            name: random_source.randbytes(solve.EXPECTED_TRANSCRIPT)
            for name in solve.DEVICE_NAMES
        }
        try:
            aead_decrypt(
                solve.derive_key(calibration_data, firmwares, fake_outputs),
                blob[4:16], blob[16:], solve.AAD,
            )
            raise AssertionError("random transcript passed authentication")
        except ValueError:
            pass

    print("[10/13] plaintext and final key are absent from release", flush=True)
    final_key = solve.derive_key(calibration_data, firmwares, outputs)
    for path in HANDOUT.rglob("*"):
        if (
            not path.is_file()
            or "_solve" in path.parts
            or path.name in {"candidate.pkg", "callback_outputs.bin"}
            or ".stage" in path.parts
        ):
            continue
        data = path.read_bytes()
        require(generate.FLAG not in data, f"plaintext flag leak: {path}")
        require(final_key not in data, f"final key leak: {path}")

    print("[11/13] release has no trace oracle or canonical-answer disclosure", flush=True)
    runner_parameters = inspect.signature(runner.run_firmware).parameters
    require("trace" not in runner_parameters, "player runner still exposes callback trace")
    runner_source = (ROOT / "author/device_runner_src/device_runner.py").read_text(encoding="utf-8")
    require(
        "UC_HOOK_MEM_WRITE" not in runner_source and 'state["trace"]' not in runner_source,
        "player runner retains an internal trace hook",
    )
    public_text = (HANDOUT / "device.json").read_text(encoding="utf-8")
    public_spec = json.loads(public_text)
    require(
        "canonical_candidate" not in public_spec
        and "canonical_events" not in public_spec
        and "%EF%BC%8E" not in public_text,
        "public spec discloses an exact exploit artifact",
    )
    exploit_needle = solve.INTENDED_OVERWRITE_PATH.encode()
    for path in HANDOUT.rglob("*"):
        if (
            path.is_file()
            and "_solve" not in path.parts
            and ".stage" not in path.parts
            and path.name not in {"candidate.pkg", "callback_outputs.bin"}
        ):
            require(exploit_needle not in path.read_bytes(), f"release leaks exact overwrite path: {path}")

    print("[12/13] fleet routes are independently selected", flush=True)
    choice_vectors = []
    for seed in generate.BUILD_SEEDS:
        _image, metadata = generate.build(seed, expected_nonce=generate.COMMON_NONCE)
        choice_vectors.append(tuple(metadata["real_choices"]))
    require(len(set(choice_vectors)) == len(solve.DEVICE_NAMES), "devices reuse one route choice vector")

    print("[13/13] restore exact clean distribution", flush=True)
    generate.main()
    require(not (HANDOUT / "candidate.pkg").exists(), "candidate package was not removed")
    require(not (HANDOUT / "callback_outputs.bin").exists(), "callback transcript was not removed")
    require(not (HANDOUT / ".stage").exists(), "staging directory was not removed")
    require(not any(
        path.name == "__pycache__" and "_solve" not in path.parts
        for path in HANDOUT.rglob("*")
    ),
            "bytecode cache was not removed")
    runtime_versions = json.loads((HANDOUT / "device.json").read_text())["runtime"]["cpython_bytecode_versions"]
    expected_root = {
        "crypto_core.py", "decrypt_flag.py", "device.json", "device_runner", "events_a.json",
        "events_b.json", "events_c.json", "extractor", "firmware_a.bin", "firmware_b.bin",
        "firmware_c.bin", "flag.enc", "normal_update.pkg", "public_key.pem", "updater", "vendor",
    }
    expected_root.update(f"device_runner.cpython-{tag}.pyc" for tag in runtime_versions)
    expected_root.update(f"updater_pipeline.cpython-{tag}.pyc" for tag in runtime_versions)
    actual_root = {path.name for path in HANDOUT.iterdir()} - {"_solve"}
    require(actual_root == expected_root, "release root contains extra files")
    clean_snapshot = {
        str(path.relative_to(HANDOUT)): hashlib.sha256(path.read_bytes()).digest()
        for path in HANDOUT.rglob("*") if path.is_file() and "_solve" not in path.parts
    }
    with tempfile.TemporaryDirectory(prefix="ghost-public-solver-") as directory:
        isolated_handout = Path(directory) / "for_user"
        shutil.copytree(HANDOUT, isolated_handout)
        shutil.copytree(ROOT / "solution", isolated_handout / "solution")
        isolated_environment = os.environ.copy()
        isolated_environment.pop("GHOST_HANDOUT_DIR", None)
        isolated_environment.pop("PYTHONPATH", None)
        isolated_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        isolated = subprocess.run(
            [sys.executable, str(isolated_handout / "solution/solver/solve.py")],
            cwd=isolated_handout,
            text=True,
            capture_output=True,
            env=isolated_environment,
        )
    require(isolated.returncode == 0 and any(
        line.startswith("SHA{") for line in isolated.stdout.splitlines()
    ), "isolated official solver failed")
    after_snapshot = {
        str(path.relative_to(HANDOUT)): hashlib.sha256(path.read_bytes()).digest()
        for path in HANDOUT.rglob("*") if path.is_file() and "_solve" not in path.parts
    }
    require(after_snapshot == clean_snapshot, "official solver contaminated the release handout")
    print("all tests passed", flush=True)


if __name__ == "__main__":
    main()
