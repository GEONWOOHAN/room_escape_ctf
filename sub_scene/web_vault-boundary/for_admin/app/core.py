from __future__ import annotations

import json
import functools
import hashlib
import hmac
import math
import os
import random
import re
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def xorshift32(value: int) -> int:
    value &= 0xFFFFFFFF
    value ^= (value << 13) & 0xFFFFFFFF
    value ^= value >> 17
    value ^= (value << 5) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def rotl32(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    amount &= 31
    if amount == 0:
        return value
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def avalanche32(value: int) -> int:
    value &= 0xFFFFFFFF
    value ^= value >> 16
    value = (value * 0x7FEB352D) & 0xFFFFFFFF
    value ^= value >> 15
    value = (value * 0x846CA68B) & 0xFFFFFFFF
    value ^= value >> 16
    return value & 0xFFFFFFFF


def layout_state(counter: int, seed: int, style: int, constants: list[int]) -> tuple[int, int]:
    if not 0 <= style < len(constants):
        raise ValueError("style 범위가 잘못되었습니다.")
    family = (style + ((counter >> 4) & 3)) & 3
    model_seed = seed >> 5
    if family == 0:
        state = xorshift32(
            model_seed ^ ((counter * 0x9E3779B9) & 0xFFFFFFFF) ^ constants[style]
        )
    elif family == 1:
        state = avalanche32(
            ((model_seed + counter * 0x85EBCA6B) & 0xFFFFFFFF)
            ^ constants[style] ^ 0xB5297A4D
        )
    elif family == 2:
        state = xorshift32(
            (rotl32(model_seed ^ constants[style], counter)
             + counter * 0xC2B2AE35 + 0x27D4EB2F) & 0xFFFFFFFF
        )
    else:
        state = avalanche32(
            rotl32((model_seed + constants[style]) & 0xFFFFFFFF, counter >> 3)
            ^ ((counter * 0x165667B1) & 0xFFFFFFFF)
            ^ 0xD3A2646C
        )
    packed = (state ^ seed) & 31
    return packed & 3, (packed >> 2) & 7


class VaultOracle:
    def __init__(self, config_path: Path | None = None):
        path = config_path or ROOT / "private" / "config.json"
        self.config = json.loads(path.read_text(encoding="utf-8"))
        self.constants = [int(value) for value in self.config["style_constants"]]
        self.bucket = int(self.config["bucket_size"])
        self.secrets = [str(value) for value in self.config["records"]]
        self.layout_records = [int(value) for value in self.config["layout_records"]]
        canonical_layout = int(self.config["canonical_layout"])
        if len(self.constants) != 4 or any(not 0 <= value <= 0xFFFFFFFF for value in self.constants):
            raise ValueError("style 상수 구성이 잘못되었습니다.")
        if self.bucket != 16:
            raise ValueError("서비스 API는 16바이트 버킷만 지원합니다.")
        if len(self.secrets) != 4 or sorted(self.layout_records) != list(range(4)):
            raise ValueError("복구 레코드 layout 구성이 잘못되었습니다.")
        if not 0 <= canonical_layout < len(self.layout_records) or self.layout_records[canonical_layout] != 0:
            raise ValueError("canonical layout이 실제 복구 레코드를 가리키지 않습니다.")
        runtime_flag = os.environ.get("FLAG")
        if runtime_flag is not None:
            if not re.fullmatch(r"SHA\{[0-9a-f]{12}-[0-9a-f]{4}\}", runtime_flag):
                raise ValueError("FLAG 형식이 잘못되었습니다.")
            self.secrets[0] = f"recovery={runtime_flag}"
        elif os.environ.get("REQUIRE_RUNTIME_FLAG") == "1":
            raise ValueError("운영 FLAG가 설정되지 않았습니다.")
        key = bytes.fromhex(str(self.config["aes_key"]))
        if len(key) != 32:
            raise ValueError("AES-256 키 길이가 잘못되었습니다.")
        # The public oracle exposes only the final ciphertext length. AES-GCM
        # preserves the plaintext length and appends a fixed 16-byte tag, so
        # performing encryption (and generating a nonce) for every measurement
        # would waste CPU without changing the observable result.
        padding_secret = os.environ.get("PADDING_SECRET")
        if padding_secret is None:
            if os.environ.get("REQUIRE_RUNTIME_PADDING") == "1":
                raise ValueError("운영 PADDING_SECRET이 설정되지 않았습니다.")
            padding_secret = str(self.config["padding_key"])
        try:
            self.padding_key = bytes.fromhex(padding_secret)
        except ValueError as error:
            raise ValueError("PADDING_SECRET 형식이 잘못되었습니다.") from error
        if len(self.padding_key) != 32:
            raise ValueError("PADDING_SECRET은 32바이트여야 합니다.")

    def _serialize(self, note: str, layout: int) -> bytes:
        selected = self.layout_records[layout]
        records: list[dict[str, str]] = []
        for index, value in enumerate(self.secrets):
            if index != selected:
                records.append({"owner": "system", "type": f"archive-{index}", "value": value})
        records.extend([
            {"owner": "administrator", "type": "recovery", "value": self.secrets[selected]},
            {
                "owner": "guest", "shared_with": "administrator",
                "title": "shared note", "value": note,
            },
        ])
        return json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _compress(plaintext: bytes) -> bytes:
        compressor = zlib.compressobj(
            level=9, method=zlib.DEFLATED, wbits=zlib.MAX_WBITS,
            memLevel=8, strategy=zlib.Z_FIXED,
        )
        return compressor.compress(plaintext) + compressor.flush()

    @functools.lru_cache(maxsize=32768)
    def _compressed_size(self, note: str, layout: int) -> int:
        """Cache the expensive, team-independent compression result.

        A score evaluates the same note and layout for a complete 16-sample
        padding epoch.  Only padding order is team-specific, so recompressing
        the identical plaintext for every sample and every team is redundant.
        """
        return len(self._compress(self._serialize(note, layout)))

    @functools.lru_cache(maxsize=8192)
    def _padding_permutation(self, context_hash: bytes, epoch: int) -> tuple[int, ...]:
        material = b"vault-boundary-padding-v2\x00" + context_hash + epoch.to_bytes(8, "big")
        seed = int.from_bytes(hmac.new(self.padding_key, material, hashlib.sha256).digest(), "big")
        values = list(range(self.bucket))
        random.Random(seed).shuffle(values)
        return tuple(values)

    def padding_noise(self, counter: int, context: bytes) -> int:
        context_hash = hashlib.sha256(context).digest()
        permutation = self._padding_permutation(context_hash, counter // self.bucket)
        return permutation[counter % self.bucket]

    def export_size(
        self,
        note: str,
        counter: int,
        seed: int,
        style: int,
        filler: int,
        noise_context: bytes = b"local-reference",
    ) -> dict[str, int]:
        if len(note.encode("utf-8")) > 512:
            raise ValueError("공유 메모가 너무 깁니다.")
        if not 0 <= seed <= 0xFFFFFFFF:
            raise ValueError("seed 범위가 잘못되었습니다.")
        if not 0 <= filler < self.bucket:
            raise ValueError("filler 범위가 잘못되었습니다.")
        layout, cover = layout_state(counter, seed, style, self.constants)
        compressed_size = self._compressed_size(note, layout)
        noise = self.padding_noise(counter, noise_context)
        # nonce (12) + compressed plaintext + padding + GCM tag (16)
        exact_size = 12 + compressed_size + filler + cover + noise + 16
        reported = math.ceil(exact_size / self.bucket) * self.bucket
        return {"size": reported, "layout": layout, "cover": cover, "noise": noise}
