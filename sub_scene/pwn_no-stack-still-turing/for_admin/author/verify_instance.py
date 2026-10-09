#!/usr/bin/env python3
import os
import json
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import config
from crypto import open_sealed, seal


def run_checker(payload, replacements=None):
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory) / "handout"
        shutil.copytree(config.DIST, work)
        (work / "payload.bin").write_bytes(payload)
        for name, value in (replacements or {}).items():
            (work / name).write_bytes(value)
        return subprocess.run(
            ["./checker"], cwd=work, text=True, capture_output=True, env=os.environ.copy()
        )


def main():
    checks = []
    memory_path = config.DIST / "memory.img"
    flag_path = config.DIST / "flag.enc"
    original_memory = memory_path.read_bytes()
    original_flag = flag_path.read_bytes()

    print("[1/9] 템플릿 실패 검사")
    template = (config.DIST / "payload.template.bin").read_bytes()
    checks.append(run_checker(template).returncode != 0)

    print("[2/9] 참조 페이로드 성공 검사")
    solution = (config.SOLUTION / "solution_payload.bin").read_bytes()
    good = run_checker(solution)
    checks.append(good.returncode == 0 and good.stdout.startswith("SHA{"))

    print("[3/9] 1비트 변조 실패 검사")
    damaged = bytearray(solution); damaged[-1] ^= 1
    checks.append(run_checker(damaged).returncode != 0)

    print("[4/9] 잘린 입력과 금지 주소 검사")
    checks.append(run_checker(solution[:-1]).returncode != 0)
    denied = bytearray(solution)
    struct.pack_into("<I", denied, 16 + 4, config.TEXT_BASE)
    checks.append(run_checker(denied).returncode != 0)

    print("[5/9] memory image 및 flag container 무결성 검사")
    damaged_memory = bytearray(original_memory)
    damaged_memory[-1] ^= 1
    checks.append(run_checker(solution, {"memory.img": bytes(damaged_memory)}).returncode != 0)
    checks.append(run_checker(solution, {"flag.enc": original_flag + b"X"}).returncode != 0)

    print("[6/9] 가변 함수 주소와 비연속 node chain 검사")
    from vm_runtime import FN_TABLE_ADDR, Memory, load_elf, execute_detailed, rol32
    target = (config.DIST / "target.elf").read_bytes()
    image = original_memory
    elf_memory = Memory()
    load_elf(elf_memory, target)
    addresses = [elf_memory.u32(FN_TABLE_ADDR + 4 * index) for index in range(config.GADGET_COUNT)]
    checks.append(len(set(addresses)) == config.GADGET_COUNT)
    checks.append(len({right - left for left, right in zip(addresses, addresses[1:])}) > 16)
    start_offset = struct.unpack_from("<I", solution, 16 + 8)[0]
    node_offsets = []
    current = start_offset
    while current != 0xFFFFFFFF and len(node_offsets) <= config.CHAIN_LENGTH:
        node_offsets.append(current)
        current = struct.unpack_from("<I", image, current + 8)[0]
    checks.append(
        len(node_offsets) == config.CHAIN_LENGTH
        and len(set(node_offsets)) == config.CHAIN_LENGTH
        and any(right != left + 0x10 for left, right in zip(node_offsets, node_offsets[1:]))
    )

    print("[6b/9] 다형 함수 레이아웃·고정 템플릿 제거 검사")
    function_words = []
    for address in addresses:
        words = []
        for index in range(200):
            word = elf_memory.u32(address + index * 4)
            words.append(word)
            if word >> 26 == 0 and word & 0x3F == 0x08:
                words.append(elf_memory.u32(address + (index + 1) * 4))
                break
        else:
            raise AssertionError("function has no bounded JR return")
        function_words.append(words)
    lengths = {len(words) for words in function_words}
    first_registers = {(words[0] >> 16) & 31 for words in function_words}
    legacy_starts = sum(
        words[0] >> 26 == 0x23
        and (words[0] >> 21) & 31 == 16
        and (words[0] >> 16) & 31 == 8
        for words in function_words
    )
    direct_rotates = sum(
        word >> 26 == 0 and word & 0x3F == 0x02 and (word >> 21) & 31 == 1
        for words in function_words for word in words
    )
    synthesized_rotates = sum(
        word >> 26 == 0 and word & 0x3F == 0x25
        for words in function_words for word in words
    )
    checks.extend((
        len(lengths) >= 10,
        len(first_registers) >= 16,
        legacy_starts == 0,
        direct_rotates >= 100,
        synthesized_rotates >= 100,
    ))

    print("[7/9] semantic alias와 terminal route receipt 검사")
    receipt_key, status, final_result = execute_detailed(target, image, solution)
    checks.append(status == 1 and receipt_key != final_result)
    private = json.loads((config.SOLUTION / "solution.json").read_text())
    alias_groups = private["alias_groups"]
    checks.append(len(alias_groups) == config.CHAIN_LENGTH)
    checks.append(all(len(group) == config.ALIAS_COUNT for group in alias_groups))
    checks.append(len(private["wrong_steps"]) == config.HEAP_WRITE_COUNT // 2)
    checks.append(tuple(private["route_target"]) == struct.unpack_from(
        "<2I", image, config.ROUTE_TARGET_ADDR - config.HEAP_BASE
    ))
    alias_payload = bytearray(solution)
    first_wrong = private["wrong_steps"][0]
    replacement_index = private["wrong_steps"].index(first_wrong)
    intended = private["intended_fn_ids"][first_wrong]
    alternative = next(value for value in alias_groups[first_wrong] if value != intended)
    function_record = 2 + replacement_index * 2
    guard_record = function_record + 1
    node_offset = private["node_offsets"][first_wrong]
    argument_offset = config.ARG_BASE_OFF + first_wrong * 0x10
    next_offset = (
        private["node_offsets"][first_wrong + 1]
        if first_wrong + 1 < config.CHAIN_LENGTH else 0xffffffff
    )
    struct.pack_into("<I", alias_payload, 16 + function_record * 12 + 8, alternative)
    struct.pack_into(
        "<I", alias_payload, 16 + guard_record * 12 + 8,
        rol32(alternative ^ argument_offset ^ next_offset ^ config.COOKIE, 7),
    )
    _alias_key, alias_status, alias_result = execute_detailed(target, image, bytes(alias_payload))
    checks.extend((alias_status == 0, alias_result == final_result, run_checker(bytes(alias_payload)).returncode != 0))

    print("[7b/9] 지급 checker는 stripped native ELF이며 VM Python source가 없음")
    description = subprocess.run(
        ["file", str(config.DIST / "checker")], text=True, capture_output=True, check=True
    ).stdout
    checks.extend(("ELF 64-bit" in description, "pie executable" in description, "stripped" in description))
    checks.extend(not (config.DIST / name).exists() for name in (
        "vm_runtime.py", "crypto.py", "loader", "checker.py", "payload.bin", "__pycache__"
    ))

    print("[7c/9] 복사된 player-side solver가 지급본만 사용하고 원본을 오염시키지 않음")
    with tempfile.TemporaryDirectory(prefix="nsst-public-solver-") as directory:
        isolated = Path(directory) / "for_user"
        shutil.copytree(config.DIST, isolated)
        shutil.copytree(config.ROOT / "solution", isolated / "solution")
        before = {
            str(path.relative_to(isolated)): path.read_bytes()
            for path in isolated.rglob("*") if path.is_file()
        }
        reference_environment = os.environ.copy()
        reference_environment.pop("NSST_HANDOUT_DIR", None)
        reference_environment.pop("PYTHONPATH", None)
        reference_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        reference = subprocess.run(
            [sys.executable, str(isolated / "solution" / "solve_reference.py")],
            cwd=isolated,
            text=True,
            capture_output=True,
            env=reference_environment,
        )
        after = {
            str(path.relative_to(isolated)): path.read_bytes()
            for path in isolated.rglob("*") if path.is_file()
        }
    checks.extend((
        reference.returncode == 0 and reference.stdout.startswith("SHA{"),
        after == before,
        not (config.DIST / "payload.bin").exists(),
    ))

    print("[8/9] ChaCha20-Poly1305 상호운용 검사")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = bytes(range(32)); nonce = bytes(range(12)); aad = b"aad"; plain = b"test-vector"
        ct, tag = seal(key, nonce, aad, plain)
        checks.append(ChaCha20Poly1305(key).encrypt(nonce, plain, aad) == ct + tag)
        checks.append(open_sealed(key, nonce, aad, ct, tag) == plain)
    except ImportError:
        checks.append(True); checks.append(True)
    print("[9/9] 지급본 비밀 및 실행 부산물 검사")
    secret = (config.PRIVATE / "flag.txt").read_bytes().strip()
    for path in config.DIST.rglob("*"):
        if "_solve" in path.parts:
            continue
        if path.is_file():
            checks.append(secret not in path.read_bytes())
            checks.append(path.name != "README.md")

    expected_release = {
        "checker", "flag.enc", "goal.pcode", "memory.img",
        "payload.template.bin", "target.elf", "vectors.bin",
    }
    actual_release = {
        str(path.relative_to(config.DIST))
        for path in config.DIST.rglob("*")
        if path.is_file() and "_solve" not in path.parts
    }
    checks.append(actual_release == expected_release)
    if not all(checks):
        print(f"검증 실패: {checks}"); raise SystemExit(1)
    print(f"검증 통과: {len(checks)}/{len(checks)}")


if __name__ == "__main__":
    main()
