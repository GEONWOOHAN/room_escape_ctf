from __future__ import annotations

import binascii
import json
import math
import os
import struct
import urllib.request
import urllib.error
import time
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HANDOUT = ROOT.parent / "for_user"
SERVER_URL = os.environ.get(
    "SERVER_URL", "http://web.roomescapectf2026.site:40569"
)
TEAM_TOKEN = os.environ.get("TEAM_TOKEN", "")
STYLE = 0
CONSTANTS = [0x6D2B79F5, 0xA511E9B3, 0x9E3779B9, 0xC0DEC0DE]


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


def layout_state(counter: int, seed: int, style: int) -> tuple[int, int]:
    if not 0 <= style < len(CONSTANTS):
        raise ValueError("invalid style")
    family = (style + ((counter >> 4) & 3)) & 3
    model_seed = seed >> 5
    if family == 0:
        state = xorshift32(
            model_seed ^ ((counter * 0x9E3779B9) & 0xFFFFFFFF) ^ CONSTANTS[style]
        )
    elif family == 1:
        state = avalanche32(
            ((model_seed + counter * 0x85EBCA6B) & 0xFFFFFFFF)
            ^ CONSTANTS[style] ^ 0xB5297A4D
        )
    elif family == 2:
        state = xorshift32(
            (rotl32(model_seed ^ CONSTANTS[style], counter)
             + counter * 0xC2B2AE35 + 0x27D4EB2F) & 0xFFFFFFFF
        )
    else:
        state = avalanche32(
            rotl32((model_seed + CONSTANTS[style]) & 0xFFFFFFFF, counter >> 3)
            ^ ((counter * 0x165667B1) & 0xFFFFFFFF)
            ^ 0xD3A2646C
        )
    packed = (state ^ seed) & 31
    return packed & 3, (packed >> 2) & 7


def handout_dir() -> Path:
    configured = os.environ.get("VAULT_HANDOUT_DIR")
    return Path(configured).resolve() if configured else DEFAULT_HANDOUT


def load_public_schema() -> dict[str, object]:
    data = (handout_dir() / "schema.wasm").read_bytes()
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise RuntimeError("올바른 WebAssembly 모듈이 아닙니다.")
    offset = 8

    def decode_u32(start: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while True:
            if start >= len(data) or shift >= 35:
                raise RuntimeError("잘못된 WebAssembly LEB128입니다.")
            byte = data[start]
            start += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, start
            shift += 7

    custom_sections: dict[bytes, bytes] = {}
    while offset < len(data):
        section_id = data[offset]
        section_size, body_start = decode_u32(offset + 1)
        body_end = body_start + section_size
        if body_end > len(data):
            raise RuntimeError("잘린 WebAssembly section입니다.")
        if section_id == 0:
            name_size, payload_start = decode_u32(body_start)
            name_end = payload_start + name_size
            if name_end > body_end:
                raise RuntimeError("잘린 WebAssembly custom section입니다.")
            custom_sections[data[payload_start:name_end]] = data[name_end:body_end]
        offset = body_end

    public = custom_sections.get(b"public", b"")
    samples = custom_sections.get(b"samples", b"")
    if len(public) < 8 or public[:4] != b"VBM1":
        raise RuntimeError("public schema evidence가 없습니다.")
    payload_length, alphabet_length, crc_id, format_length = public[4:8]
    expected_public = 8 + alphabet_length + format_length
    if len(public) != expected_public or crc_id != 1:
        raise RuntimeError("public schema evidence가 손상되었습니다.")
    alphabet = public[8:8 + alphabet_length].decode("ascii")
    flag_format = public[8 + alphabet_length:].decode("ascii")

    if len(samples) < 8 or samples[:4] != b"VBS1":
        raise RuntimeError("calibration evidence가 없습니다.")
    note_length, sample_count = struct.unpack_from("<HH", samples, 4)
    sample_start = 8 + note_length
    if len(samples) != sample_start + sample_count * 12:
        raise RuntimeError("calibration evidence가 손상되었습니다.")
    note = samples[8:sample_start].decode("utf-8")
    observations = []
    for index in range(sample_count):
        counter, seed, style, filler, size = struct.unpack_from(
            "<IIBBH", samples, sample_start + index * 12
        )
        observations.append({
            "counter": counter,
            "seed": seed,
            "style": style,
            "filler": filler,
            "size": size,
        })
    return {
        "format": flag_format,
        "payload_alphabet": alphabet,
        "payload_length": payload_length,
        "crc": "CRC-16/CCITT-FALSE over payload ASCII",
        "calibration": {"note": note, "observations": observations},
    }


def infer_oracle_parameters(schema: dict[str, object]) -> tuple[int, int, int]:
    calibration = schema.get("calibration")
    if not isinstance(calibration, dict):
        raise RuntimeError("calibration evidence가 없습니다.")
    observations = calibration.get("observations")
    if not isinstance(observations, list) or len(observations) < 32:
        raise RuntimeError("calibration 표본이 부족합니다.")
    counters = [int(item["counter"]) for item in observations]
    if counters != list(range(counters[0], counters[0] + len(counters))):
        raise RuntimeError("calibration counter가 연속적이지 않습니다.")
    sizes = [int(item["size"]) for item in observations]
    bucket = math.gcd(*sizes)
    if bucket <= 1:
        raise RuntimeError("reported-size bucket을 추론하지 못했습니다.")

    stable_periods = []
    for period in range(2, len(sizes) // 2 + 1):
        if len(sizes) % period:
            continue
        totals = [sum(sizes[start:start + period]) for start in range(0, len(sizes), period)]
        if len(totals) >= 3 and len(set(totals)) == 1:
            stable_periods.append(period)
    if bucket not in stable_periods:
        raise RuntimeError("balanced-noise epoch을 추론하지 못했습니다.")
    epoch_size = bucket

    states = {
        layout_state(
            int(item["counter"]), int(item["seed"]), int(item["style"])
        )
        for item in observations
    }
    if len(states) != 1:
        raise RuntimeError("calibration layout이 일관되지 않습니다.")
    layout, cover = states.pop()
    if cover != 0:
        raise RuntimeError("calibration cover가 안정적이지 않습니다.")
    return layout, bucket, epoch_size


def safe_seed(counter: int, layout: int) -> int:
    for seed in range(4096):
        actual_layout, cover = layout_state(counter, seed, STYLE)
        if actual_layout == layout and cover == 0:
            return seed
    raise RuntimeError("적절한 seed를 찾지 못했습니다.")


class Transport(Protocol):
    counter: int
    requests: int

    def share(self, value: str) -> None: ...

    def export(self, seed: int, style: int, filler: int) -> int: ...


class HttpTransport:
    def __init__(self):
        if not TEAM_TOKEN:
            raise RuntimeError("TEAM_TOKEN 환경 변수가 필요합니다.")
        status = self._post("/api/session", {})
        self.session = str(status["session"])
        self.counter = int(status["counter"])
        self.requests = 0

    def _post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        headers = {"Content-Type": "application/json"}
        if path == "/api/session":
            headers["X-Team-Token"] = TEAM_TOKEN
        else:
            headers["X-Team-Session"] = self.session
        last_error: Exception | None = None
        for attempt in range(5):
            request = urllib.request.Request(
                SERVER_URL.rstrip("/") + path,
                data=json.dumps(body).encode(),
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return json.loads(response.read().decode())
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in {408, 429, 500, 502, 503, 504}:
                    raise
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                last_error = error
            time.sleep(0.25 * (2 ** attempt))
        raise RuntimeError(f"서버 요청 재시도 실패: {last_error}")

    def share(self, value: str) -> None:
        self._post("/api/share", {"value": value})

    def export(self, seed: int, style: int, filler: int) -> int:
        result = self._post("/api/export-size", {"seed": seed, "style": style, "filler": filler})
        self.counter = int(result["next_counter"])
        self.requests += 1
        return int(result["size"])

    def measure(self, value: str, exports: list[tuple[int, int, int]]) -> list[int]:
        result = self._post(
            "/api/measure",
            {
                "value": value,
                "exports": [
                    {"seed": seed, "style": style, "filler": filler}
                    for seed, style, filler in exports
                ],
            },
        )
        self.counter = int(result["next_counter"])
        self.requests += len(exports)
        return [int(value) for value in result["sizes"]]

    def measure_batch(
        self, groups: list[tuple[str, list[tuple[int, int, int]]]]
    ) -> list[list[int]]:
        result = self._post(
            "/api/measure-batch",
            {
                "measurements": [
                    {
                        "value": value,
                        "exports": [
                            {"seed": seed, "style": style, "filler": filler}
                            for seed, style, filler in exports
                        ],
                    }
                    for value, exports in groups
                ]
            },
        )
        self.counter = int(result["next_counter"])
        self.requests += sum(len(exports) for _, exports in groups)
        return [
            [int(value) for value in sizes]
            for sizes in result["measurements"]
        ]


def score(transport: Transport, note: str, layout: int, bucket: int) -> int:
    if transport.counter % bucket:
        raise RuntimeError("측정은 16요청 epoch 경계에서 시작해야 합니다.")
    if hasattr(transport, "measure"):
        exports = [
            (safe_seed(transport.counter + offset, layout), STYLE, 0)
            for offset in range(bucket)
        ]
        return sum(transport.measure(note, exports))
    transport.share(note)
    total = 0
    for _ in range(bucket):
        seed = safe_seed(transport.counter, layout)
        total += transport.export(seed, STYLE, 0)
    return total


def score_many(
    transport: Transport, notes: list[str], layout: int, bucket: int
) -> list[int]:
    if not notes:
        return []
    if hasattr(transport, "measure_batch"):
        groups: list[tuple[str, list[tuple[int, int, int]]]] = []
        counter = transport.counter
        for note in notes:
            if counter % bucket:
                raise RuntimeError("측정은 16요청 epoch 경계에서 시작해야 합니다.")
            exports = [
                (safe_seed(counter + offset, layout), STYLE, 0)
                for offset in range(bucket)
            ]
            groups.append((note, exports))
            counter += bucket
        return [sum(sizes) for sizes in transport.measure_batch(groups)]
    return [score(transport, note, layout, bucket) for note in notes]


def align_epoch(transport: Transport, layout: int, bucket: int) -> None:
    remaining = (-transport.counter) % bucket
    if not remaining:
        return
    if hasattr(transport, "measure"):
        exports = [
            (safe_seed(transport.counter + offset, layout), STYLE, 0)
            for offset in range(remaining)
        ]
        transport.measure("", exports)
        return
    transport.share("")
    for _ in range(remaining):
        seed = safe_seed(transport.counter, layout)
        transport.export(seed, STYLE, 0)


def solve(transport: Transport) -> tuple[str, int]:
    schema = load_public_schema()
    alphabet = str(schema["payload_alphabet"])
    length = int(schema["payload_length"])
    layout, _reported_bucket, epoch_size = infer_oracle_parameters(schema)
    public_flag_prefix = str(schema["format"]).split("<payload>", 1)[0]
    prefix = "recovery=" + public_flag_prefix
    align_epoch(transport, layout, epoch_size)
    paths = [""]

    for depth in range(length):
        candidate_values: list[str] = []
        for path in paths:
            for character in alphabet:
                candidate_values.append(path + character)
        scores: list[int] = []
        for start in range(0, len(candidate_values), 16):
            scores.extend(score_many(
                transport,
                [prefix + candidate for candidate in candidate_values[start:start + 16]],
                layout,
                epoch_size,
            ))
        candidates = list(zip(scores, candidate_values))
        best = min(value for value, _ in candidates)
        paths = list(dict.fromkeys(candidate for value, candidate in candidates if value == best))[:16]
        print(f"[{depth + 1}/{length}] 후보 {len(paths)}개 | 요청 {transport.requests}", flush=True)

    flags: list[str] = []
    notes: list[str] = []
    for payload in paths:
        crc = binascii.crc_hqx(payload.encode(), 0xFFFF)
        flag = f"SHA{{{payload}-{crc:04x}}}"
        flags.append(flag)
        notes.append(f"recovery={flag}")
    final_scores = score_many(transport, notes, layout, epoch_size)
    finals = list(zip(final_scores, flags))
    finals.sort()
    if len(finals) > 1 and finals[0][0] == finals[1][0]:
        raise RuntimeError("최종 후보가 하나로 결정되지 않았습니다.")
    return finals[0][1], transport.requests


def main() -> None:
    flag, requests = solve(HttpTransport())
    print(flag)
    print(f"요청 수: {requests}")


if __name__ == "__main__":
    main()
