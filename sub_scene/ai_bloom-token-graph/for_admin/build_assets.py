from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
from pathlib import Path

from challenge.core import Tokenizer


ROOT = Path(__file__).resolve().parent
HANDOUT = ROOT / ".build" / "for_user"
PUBLIC_HANDOUT = ROOT.parent / "for_user"
PRIVATE = ROOT / "private"
NATIVE = ROOT / "native"

POOL_SIZE = 128
MASTER_SEED = 0xB1006A7E20260911
PAYLOAD_LENGTH = 18
BUDGET = 2000
BLOOM_BITS = 4096
TARGET_DENSITY = 0.24
STYLE_CONSTANTS = [0x7F4A7C15, 0x91E10DA5, 0xD192ED03, 0x6C8E9CF5]
PAYLOAD_TOKENS = [f"{left}{right}" for left in "ab" for right in "abcdefghijklmnop"]
GENERAL_TOKENS = [
    "assistant", "says", "end", "of", "response", "analysis", "result", "complete",
    "system", "notice", "secure", "filter", "generated", "output", "lock", "audit",
    "training", "data", "memory", "check",
]
STRUCTURAL_TOKENS = ["sha", "{", "v3", "_", ":", "done", "}"]
SCOREBOARD_FLAG = "SHA{bl00m_0r4cl3_tr4c3s_t0k3n_gr4phs}"


def publish_handout() -> None:
    """Copy a complete admin-side build into the public handout directory."""
    if not HANDOUT.is_dir():
        raise RuntimeError("admin handout build is missing")
    if PUBLIC_HANDOUT.exists():
        if PUBLIC_HANDOUT.is_symlink() or not PUBLIC_HANDOUT.is_dir():
            raise RuntimeError(f"refusing to replace non-directory release path: {PUBLIC_HANDOUT}")
        shutil.rmtree(PUBLIC_HANDOUT)
    shutil.copytree(HANDOUT, PUBLIC_HANDOUT)


def encode_u32(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def make_vocab() -> list[str]:
    values = STRUCTURAL_TOKENS + PAYLOAD_TOKENS + GENERAL_TOKENS
    rng = random.Random(MASTER_SEED ^ 0x564F434142)
    rng.shuffle(values)
    return ["<unk>", *values]


def token_ids(tokens: list[str], mapping: dict[str, int]) -> list[int]:
    return [mapping[token] for token in tokens]


def mutate_tail(real: list[str], start: int, length: int, rng: random.Random, first_choices: list[str]) -> list[str]:
    first = first_choices.pop()
    tail = [first]
    while len(tail) < length:
        tail.append(rng.choice(PAYLOAD_TOKENS))
    return [*real[:start], *tail]


def make_instance(seed: int, mapping: dict[str, int]) -> dict[str, object]:
    rng = random.Random(seed)
    payload = [rng.choice(PAYLOAD_TOKENS) for _ in range(PAYLOAD_LENGTH)]
    prefix = ["sha", "{", "v3", "_"]
    documents = [token_ids([*prefix, *payload, "}"], mapping)]

    # The amount and location of short-lived branches intentionally varies by seed.
    partial_starts = sorted(rng.sample(range(3, 14), rng.randrange(3, 6)))
    for start in partial_starts:
        alternatives = [token for token in PAYLOAD_TOKENS if token != payload[start]]
        rng.shuffle(alternatives)
        trap = mutate_tail(payload, start, 2, rng, alternatives)
        documents.append(token_ids([*prefix, *trap], mapping))

    # Eight to ten complete near-neighbours survive to the final claim endpoint.
    alternatives = [token for token in PAYLOAD_TOKENS if token != payload[14]]
    rng.shuffle(alternatives)
    full_decoy_count = rng.randrange(8, 11)
    for _ in range(full_decoy_count):
        decoy = mutate_tail(payload, 14, PAYLOAD_LENGTH - 14, rng, alternatives)
        documents.append(token_ids([*prefix, *decoy, "}"], mapping))

    return {
        "seed": f"0x{seed:016x}",
        "payload": payload,
        "documents": documents,
        "salts": [rng.randbytes(16).hex() for _ in range(3)],
        "filter_seeds": [rng.randrange(1 << 63) for _ in range(3)],
        "partial_decoys": len(partial_starts),
        "full_decoys": full_decoy_count,
    }


def write_tokenizer_header(vocab: list[str]) -> Path:
    path = NATIVE / "tokenizer_data.h"
    strings = ",\n    ".join(json.dumps(token) for token in vocab)
    lengths = ", ".join(str(len(token.encode("ascii"))) for token in vocab)
    path.write_text(
        "#include <stdint.h>\n"
        f"#define VOCAB_COUNT {len(vocab)}u\n"
        f"static const char *const VOCAB[VOCAB_COUNT] = {{\n    {strings}\n}};\n"
        f"static const uint16_t VOCAB_LENGTHS[VOCAB_COUNT] = {{{lengths}}};\n",
        encoding="utf-8",
    )
    return path


def build_wasm(vocab: list[str]) -> None:
    if shutil.which("clang") is None:
        raise RuntimeError("clang with the wasm32 target is required to rebuild normalizer.wasm")
    header = write_tokenizer_header(vocab)
    try:
        subprocess.run(
            [
                "clang", "--target=wasm32", "-Oz", "-nostdlib", "-fno-builtin",
                "-Wl,--no-entry", "-Wl,--export-memory", "-Wl,--initial-memory=131072",
                "-Wl,--max-memory=131072", "-Wl,--strip-all",
                "-I", str(NATIVE), str(NATIVE / "normalizer.c"),
                "-o", str(HANDOUT / "normalizer.wasm"),
            ],
            check=True,
        )
        lexicon = b"BTG3LEX" + len(vocab).to_bytes(2, "little")
        for token in vocab:
            raw = token.encode("ascii")
            lexicon += bytes([len(raw)]) + raw
        name = b"lexicon"
        custom = encode_u32(len(name)) + name + lexicon
        with (HANDOUT / "normalizer.wasm").open("ab") as output:
            output.write(b"\x00" + encode_u32(len(custom)) + custom)
    finally:
        header.unlink(missing_ok=True)


def build_examples(tokenizer: Tokenizer) -> list[dict[str, object]]:
    samples = [
        "SHA{V3_aa ab ac ad}",
        "%53%48%41%7BV3_aa_ab_ac%7D",
        "ASSISTANT   SAYS: secure-response",
        "analysis.result::complete",
        "sha { v3 _ aa ab ac",
        "SYSTEM_notice__generated output",
    ]
    return [
        {
            "input": sample,
            "normalized": tokenizer.normalize(sample),
            "token_ids": tokenizer.tokenize(sample),
        }
        for sample in samples
    ]


def main() -> None:
    print("[1/5] 출력 디렉터리 초기화")
    if HANDOUT.exists():
        for child in HANDOUT.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        HANDOUT.mkdir(parents=True)
    if PRIVATE.exists():
        shutil.rmtree(PRIVATE)
    PRIVATE.mkdir(parents=True)

    print("[2/5] 실제 WASM tokenizer 빌드")
    vocab = make_vocab()
    tokenizer = Tokenizer(vocab)
    build_wasm(vocab)

    print("[3/5] 128개 팀별 인스턴스 pool 생성")
    mapping = {token: index for index, token in enumerate(vocab)}
    seed_rng = random.Random(MASTER_SEED)
    seeds: set[int] = set()
    while len(seeds) < POOL_SIZE:
        seeds.add(seed_rng.randrange(1 << 63))
    instances = [make_instance(seed, mapping) for seed in sorted(seeds)]
    private = {
        "version": 4,
        "budget": BUDGET,
        "payload_length": PAYLOAD_LENGTH,
        "bloom_bits": BLOOM_BITS,
        "target_density": TARGET_DENSITY,
        "style_constants": STYLE_CONSTANTS,
        "vocab": vocab,
        "session_secret": hashlib.sha256(f"session:{MASTER_SEED}".encode()).hexdigest(),
        "deployment_id": "development-v4",
        "scoreboard_flag": SCOREBOARD_FLAG,
        "instances": instances,
    }
    (PRIVATE / "pool.json").write_text(
        json.dumps(private, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    print("[4/5] 플레이어 분석 자료 생성")
    public_tokens = list(vocab[1:])
    random.Random(MASTER_SEED ^ 0x5055424C4943).shuffle(public_tokens)
    (HANDOUT / "vocab.txt").write_text("\n".join(public_tokens) + "\n", encoding="utf-8")
    (HANDOUT / "examples.json").write_text(
        json.dumps(build_examples(tokenizer), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (HANDOUT / "challenge.json").write_text(
        json.dumps(
            {
                "version": 4,
                "payload_tokens": PAYLOAD_LENGTH,
                "window_tokens": 5,
                "profiles": ["A", "B", "C"],
                "routing": "FNV-1a32(big-endian uint16 token ids) mod 3: AB, BC, AC",
                "request_budget": BUDGET,
                "budget_scope": "all generate and claim requests, cumulative per team",
                "session_header": "X-Team-Token",
                "session_endpoint": "POST /api/session",
                "query_endpoint": "POST /api/generate",
                "claim_endpoint": "POST /api/claim",
                "claim_body": {"payload": "<18 concatenated payload tokens>"},
                "claim_gate": (
                    "all reachable graph shingles must first be resolved: one routed allowed "
                    "response, or blocked responses from both routed profiles"
                ),
                "scoreboard_flag_format": "SHA{...}",
                "note": "Only an output that normalizes to exactly one 5-token window is tested.",
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["gcc", "-O2", "-s", "-DHARD_VARIANT", str(NATIVE / "generator.c"), "-o", str(HANDOUT / "generator")],
        check=True,
    )

    print("[5/5] 완료")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Bloom Token Graph inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after building, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    main()
    if arguments.publish:
        publish_handout()
