from __future__ import annotations

import http.client
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HANDOUT = Path(os.environ.get("BTG_HANDOUT_DIR", ROOT.parent / "for_user")).resolve()
PROFILES = ("A", "B", "C")
STYLE = 0
STYLE_CONSTANTS = [0x7F4A7C15, 0x91E10DA5, 0xD192ED03, 0x6C8E9CF5]
PAYLOAD_LENGTH = 18
_TOKEN_ID_CACHE: dict[tuple[str, ...], dict[str, int]] = {}


def pack_shingle(token_ids: tuple[int, ...] | list[int]) -> bytes:
    """Encode the five IDs as documented in public challenge.json."""
    if len(token_ids) != 5:
        raise ValueError("5-token windows only")
    return b"".join(int(token_id).to_bytes(2, "big") for token_id in token_ids)


def fnv1a32(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def route_profiles(packed: bytes) -> tuple[int, int]:
    return ((0, 1), (1, 2), (0, 2))[fnv1a32(packed) % 3]


def xorshift32(value: int) -> int:
    value &= 0xFFFFFFFF
    value ^= (value << 13) & 0xFFFFFFFF
    value ^= value >> 17
    value ^= (value << 5) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def template_index(seed: int, counter: int, style: int) -> int:
    """Recovered from the distributed stripped generator executable."""
    if not 0 <= style < len(STYLE_CONSTANTS):
        raise ValueError("invalid style")
    return xorshift32(
        (seed ^ counter ^ STYLE_CONSTANTS[style]) & 0xFFFFFFFF
    ) & 7


def _decode_u32(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7


def _wasm_lexicon() -> list[str]:
    data = (HANDOUT / "normalizer.wasm").read_bytes()
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        size, body = _decode_u32(data, offset + 1)
        end = body + size
        if section_id == 0:
            name_size, cursor = _decode_u32(data, body)
            name = data[cursor:cursor + name_size]
            payload = data[cursor + name_size:end]
            if name == b"lexicon" and payload.startswith(b"BTG3LEX"):
                count = int.from_bytes(payload[7:9], "little")
                cursor = 9
                result = []
                for _ in range(count):
                    length = payload[cursor]
                    cursor += 1
                    result.append(payload[cursor:cursor + length].decode("ascii"))
                    cursor += length
                if cursor != len(payload):
                    raise RuntimeError("trailing lexicon data")
                return result
        offset = end
    raise RuntimeError("WASM lexicon section not found")


def recover_token_ids(tokens: list[str]) -> dict[str, int]:
    cache_key = tuple(tokens)
    if cache_key in _TOKEN_ID_CACHE:
        return _TOKEN_ID_CACHE[cache_key]
    lexicon = _wasm_lexicon()
    all_ids = {token: index for index, token in enumerate(lexicon)}
    mapping = {token: all_ids[token] for token in tokens}
    _TOKEN_ID_CACHE[cache_key] = mapping
    return mapping


class Transport:
    counter: int
    requests: int

    def query(self, profile: str, prompt: str, seed: int, style: int) -> bool:
        raise NotImplementedError

    def claim(self, payload: str) -> str | None:
        raise NotImplementedError


class LocalTransport(Transport):
    def __init__(self, service: Any, team_token: str = "reference-team-000"):
        self.service = service
        session = service.new_session(team_token)
        self.session_id = str(session["session"])
        self.counter = int(session["counter"])
        self.requests = 0

    def query(self, profile: str, prompt: str, seed: int, style: int) -> bool:
        result = self.service.generate(self.session_id, profile, prompt, seed, style)
        self.counter = int(result["next_counter"])
        self.requests += 1
        return result["status"] == "blocked"

    def claim(self, payload: str) -> str | None:
        result = self.service.claim(self.session_id, payload)
        self.counter = int(result["next_counter"])
        self.requests += 1
        return str(result["flag"]) if result["status"] == "accepted" else None


class HttpTransport(Transport):
    def __init__(self, base_url: str, team_token: str):
        self.base_url = base_url.rstrip("/")
        self.team_token = team_token
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("invalid SERVER_URL")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_path = parsed.path.rstrip("/")
        self.connection: http.client.HTTPConnection | None = None
        session = self._post("/api/session", {})
        self.session_id = str(session["session"])
        self.counter = int(session["counter"])
        self.requests = 0

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        last_error: Exception | None = None
        for attempt in range(5):
            try:
                if self.connection is None:
                    connection_type = (
                        http.client.HTTPSConnection if self.scheme == "https"
                        else http.client.HTTPConnection
                    )
                    self.connection = connection_type(self.host, self.port, timeout=30)
                self.connection.request(
                    "POST",
                    self.base_path + path,
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "X-Team-Token": self.team_token,
                    },
                )
                response = self.connection.getresponse()
                raw = response.read()
                if response.status != 200:
                    raise RuntimeError(
                        f"HTTP {response.status}: {raw[:200].decode('utf-8', errors='replace')}"
                    )
                return json.loads(raw.decode("utf-8"))
            except (OSError, http.client.HTTPException) as error:
                last_error = error
                if self.connection is not None:
                    self.connection.close()
                self.connection = None
                time.sleep(0.1 * (2 ** attempt))
        raise RuntimeError(f"server request failed after retries: {last_error}")

    def query(self, profile: str, prompt: str, seed: int, style: int) -> bool:
        result = self._post(
            "/api/generate",
            {
                "session": self.session_id,
                "profile": profile,
                "prompt": prompt,
                "seed": seed,
                "style": style,
            },
        )
        self.counter = int(result["next_counter"])
        self.requests += 1
        return result["status"] == "blocked"

    def claim(self, payload: str) -> str | None:
        result = self._post("/api/claim", {"session": self.session_id, "payload": payload})
        self.counter = int(result["next_counter"])
        self.requests += 1
        return str(result["flag"]) if result["status"] == "accepted" else None


@dataclass
class SolveResult:
    flag: str
    payload: str
    requests: int
    peak_paths: int
    completed_paths: int


class GraphSolver:
    def __init__(self, transport: Transport, verbose: bool = True):
        self.transport = transport
        self.verbose = verbose
        public_vocab = [
            line.strip()
            for line in (HANDOUT / "vocab.txt").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        required = list(dict.fromkeys(["sha", "{", "v3", "_", "}", *public_vocab]))
        self.ids = recover_token_ids(required)
        self.payload_tokens = sorted(
            (token for token in public_vocab if re.fullmatch(r"[ab][a-p]", token)),
            key=lambda token: self.ids[token],
        )
        if len(self.payload_tokens) != 32:
            raise RuntimeError("payload vocabulary recovery failed")
        self.cache: dict[tuple[str, ...], bool] = {}
        self.peak_paths = 1

    def _seed(self) -> int:
        return next(
            seed for seed in range(4096)
            if template_index(seed, self.transport.counter, STYLE) == 0
        )

    def _edge_exists(self, shingle: tuple[str, ...]) -> bool:
        if shingle in self.cache:
            return self.cache[shingle]
        token_ids = tuple(self.ids[token] for token in shingle)
        route = route_profiles(pack_shingle(token_ids))
        prompt = " ".join(shingle)
        first, second = route
        result = self.transport.query(PROFILES[first], prompt, self._seed(), STYLE)
        if result:
            result = self.transport.query(PROFILES[second], prompt, self._seed(), STYLE)
        self.cache[shingle] = result
        return result

    def solve(self) -> SolveResult:
        prefix = ("sha", "{", "v3", "_")
        paths: list[tuple[str, ...]] = [prefix]
        for depth in range(PAYLOAD_LENGTH):
            expanded: list[tuple[str, ...]] = []
            for path in paths:
                for token in self.payload_tokens:
                    if self._edge_exists((*path[-4:], token)):
                        expanded.append((*path, token))
            paths = list(dict.fromkeys(expanded))
            if not paths or len(paths) > 512:
                raise RuntimeError(f"invalid graph width at depth {depth + 1}: {len(paths)}")
            self.peak_paths = max(self.peak_paths, len(paths))
            if self.verbose:
                print(
                    f"payload[{depth + 1:02d}/{PAYLOAD_LENGTH}] "
                    f"paths={len(paths)} requests={self.transport.requests}",
                    flush=True,
                )

        completed = [path for path in paths if self._edge_exists((*path[-4:], "}"))]
        for path in completed:
            payload = "".join(path[len(prefix):])
            flag = self.transport.claim(payload)
            if flag is not None:
                return SolveResult(flag, payload, self.transport.requests, self.peak_paths, len(completed))
        raise RuntimeError(f"none of {len(completed)} completed paths passed claim")


def solve_http() -> SolveResult:
    base_url = os.environ.get("SERVER_URL", "http://ai.roomescapectf2026.site:40542")
    team_token = os.environ.get("TEAM_TOKEN", "").strip()
    if not team_token:
        raise RuntimeError("TEAM_TOKEN environment variable is required")
    return GraphSolver(HttpTransport(base_url, team_token)).solve()
