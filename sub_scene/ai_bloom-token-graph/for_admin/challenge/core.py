from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import re
import sqlite3
import struct
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("A", "B", "C")
SHINGLE_SIZE = 5
TEAM_ID_RE = re.compile(r"[0-9a-f]{64}")


class Tokenizer:
    """Python mirror of the freestanding tokenizer compiled into normalizer.wasm."""

    def __init__(self, vocab: list[str]):
        self.vocab = vocab
        self.matches = sorted(
            ((token.encode("ascii"), index) for index, token in enumerate(vocab) if token != "<unk>"),
            key=lambda item: (-len(item[0]), item[1]),
        )

    @staticmethod
    def normalize_bytes(text: str) -> bytes:
        raw = urllib.parse.unquote_to_bytes(text)
        output = bytearray()
        pending_space = False
        for value in raw:
            if 0x41 <= value <= 0x5A:
                value += 0x20
            allowed = 0x61 <= value <= 0x7A or 0x30 <= value <= 0x39 or value in b"{}_:" 
            if allowed:
                if pending_space and output:
                    output.append(0x20)
                output.append(value)
                pending_space = False
            else:
                pending_space = True
        return bytes(output)

    def normalize(self, text: str) -> str:
        return self.normalize_bytes(text).decode("ascii")

    def tokenize(self, text: str) -> list[int]:
        result: list[int] = []
        for part in self.normalize_bytes(text).split():
            cursor = 0
            while cursor < len(part):
                for token, token_id in self.matches:
                    if part.startswith(token, cursor):
                        result.append(token_id)
                        cursor += len(token)
                        break
                else:
                    result.append(0)
                    cursor += 1
        return result


def pack_shingle(token_ids: tuple[int, ...] | list[int]) -> bytes:
    if len(token_ids) != SHINGLE_SIZE:
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


def template_index(seed: int, counter: int, style: int, constants: list[int]) -> int:
    if not 0 <= style < len(constants):
        raise ValueError("invalid style")
    return xorshift32((seed ^ counter ^ constants[style]) & 0xFFFFFFFF) & 7


class BloomFilter:
    def __init__(self, size_bits: int, salt: bytes):
        self.size_bits = size_bits
        self.salt = salt
        self.bits = bytearray((size_bits + 7) // 8)
        self.values: set[bytes] = set()

    def _indexes(self, value: bytes) -> list[int]:
        digest = hashlib.sha256(self.salt + value).digest()
        return [struct.unpack_from("!I", digest, index * 4)[0] % self.size_bits for index in range(4)]

    def add(self, value: bytes) -> bool:
        if value in self.values:
            return False
        self.values.add(value)
        for index in self._indexes(value):
            self.bits[index // 8] |= 1 << (index % 8)
        return True

    def contains(self, value: bytes) -> bool:
        return all(self.bits[index // 8] & (1 << (index % 8)) for index in self._indexes(value))

    @property
    def density(self) -> float:
        return sum(byte.bit_count() for byte in self.bits) / self.size_bits


@dataclass(frozen=True)
class TeamState:
    team_id: str
    instance_index: int
    counter: int
    remaining: int
    solved: bool


class TeamStore:
    """SQLite-backed assignment and request budget shared by all HTTP connections."""

    def __init__(self, path: str | Path, pool_size: int, budget: int, namespace: str = "development"):
        self.pool_size = pool_size
        self.budget = budget
        self.lock = threading.RLock()
        suffix = hashlib.sha256(namespace.encode("utf-8")).hexdigest()[:16]
        self.table = f"teams_{suffix}"
        self.probe_table = f"probes_{suffix}"
        self.db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute(
            f"CREATE TABLE IF NOT EXISTS {self.table} ("
            "team_id TEXT PRIMARY KEY, instance_index INTEGER NOT NULL UNIQUE, "
            "counter INTEGER NOT NULL, remaining INTEGER NOT NULL, solved INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.execute(
            f"CREATE TABLE IF NOT EXISTS {self.probe_table} ("
            "team_id TEXT NOT NULL, shingle BLOB NOT NULL, profile INTEGER NOT NULL, "
            "blocked INTEGER NOT NULL, PRIMARY KEY(team_id,shingle,profile))"
        )

    @staticmethod
    def _row(row: tuple[object, ...]) -> TeamState:
        return TeamState(str(row[0]), int(row[1]), int(row[2]), int(row[3]), bool(row[4]))

    def get_or_assign(self, team_id: str) -> TeamState:
        if not TEAM_ID_RE.fullmatch(team_id):
            raise ValueError("invalid team identity")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    f"SELECT team_id,instance_index,counter,remaining,solved FROM {self.table} WHERE team_id=?",
                    (team_id,),
                ).fetchone()
                if row is None:
                    occupied = {
                        int(item[0])
                        for item in self.db.execute(f"SELECT instance_index FROM {self.table}")
                    }
                    start = int.from_bytes(hashlib.sha256(bytes.fromhex(team_id)).digest()[:4], "big") % self.pool_size
                    instance_index = next(
                        (candidate for offset in range(self.pool_size)
                         if (candidate := (start + offset) % self.pool_size) not in occupied),
                        None,
                    )
                    if instance_index is None:
                        raise RuntimeError("instance pool exhausted")
                    self.db.execute(
                        f"INSERT INTO {self.table}(team_id,instance_index,counter,remaining,solved) "
                        "VALUES(?,?,?,?,0)",
                        (team_id, instance_index, 0, self.budget),
                    )
                    row = (team_id, instance_index, 0, self.budget, 0)
                self.db.execute("COMMIT")
                return self._row(row)
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def consume(self, team_id: str) -> TeamState:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    f"SELECT team_id,instance_index,counter,remaining,solved FROM {self.table} WHERE team_id=?",
                    (team_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("unknown team")
                state = self._row(row)
                if state.remaining <= 0:
                    raise ValueError("request budget exhausted")
                self.db.execute(
                    f"UPDATE {self.table} SET counter=counter+1, remaining=remaining-1 WHERE team_id=?",
                    (team_id,),
                )
                self.db.execute("COMMIT")
                return TeamState(team_id, state.instance_index, state.counter, state.remaining - 1, state.solved)
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def mark_solved(self, team_id: str) -> None:
        with self.lock:
            self.db.execute(f"UPDATE {self.table} SET solved=1 WHERE team_id=?", (team_id,))

    def record_probe(self, team_id: str, shingle: bytes, profile: int, blocked: bool) -> None:
        with self.lock:
            self.db.execute(
                f"INSERT INTO {self.probe_table}(team_id,shingle,profile,blocked) VALUES(?,?,?,?) "
                "ON CONFLICT(team_id,shingle,profile) DO UPDATE SET blocked=excluded.blocked",
                (team_id, shingle, profile, int(blocked)),
            )

    def probe_rows(self, team_id: str) -> list[tuple[bytes, int, bool]]:
        with self.lock:
            rows = self.db.execute(
                f"SELECT shingle,profile,blocked FROM {self.probe_table} WHERE team_id=?",
                (team_id,),
            ).fetchall()
        return [(bytes(row[0]), int(row[1]), bool(row[2])) for row in rows]


class ChallengeService:
    def __init__(self, state_path: str | Path | None = None):
        self.private = json.loads((ROOT / "private" / "pool.json").read_text(encoding="utf-8"))
        self.instances = list(self.private["instances"])
        self.vocab = [str(value) for value in self.private["vocab"]]
        self.tokenizer = Tokenizer(self.vocab)
        self.style_constants = [int(value) for value in self.private["style_constants"]]
        self.budget = int(self.private["budget"])
        default_state = os.environ.get("STATE_DB", str(ROOT / "private" / "runtime_state.sqlite3"))
        deployment_id = os.environ.get(
            "DEPLOYMENT_ID", str(self.private.get("deployment_id", "development"))
        )
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", deployment_id):
            raise ValueError("invalid DEPLOYMENT_ID")
        self.store = TeamStore(
            state_path if state_path is not None else default_state,
            len(self.instances),
            self.budget,
            deployment_id,
        )
        secret_hex = os.environ.get("SESSION_SECRET", str(self.private["session_secret"]))
        self.session_secret = bytes.fromhex(secret_hex)
        scoreboard_flag = os.environ.get("SCOREBOARD_FLAG", str(self.private["scoreboard_flag"]))
        if not re.fullmatch(r"SHA\{[^{}]{8,160}\}", scoreboard_flag):
            raise ValueError("SCOREBOARD_FLAG must use SHA{...} format")
        self.scoreboard_flag = scoreboard_flag
        self.filter_cache: dict[int, list[BloomFilter]] = {}
        self.coverage_cache: dict[int, dict[bytes, tuple[int, int]]] = {}
        self.filter_lock = threading.Lock()

    @staticmethod
    def team_identity(team_token: str) -> str:
        if not (8 <= len(team_token) <= 256 or
                re.fullmatch(r"ctfd-[1-9][0-9]*", team_token)):
            raise ValueError("invalid team token")
        return hashlib.sha256(b"bloom-token-team\x00" + team_token.encode("utf-8")).hexdigest()

    def _session_token(self, team_id: str) -> str:
        raw = bytes.fromhex(team_id)
        body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        signature = hmac.new(self.session_secret, raw, hashlib.sha256).hexdigest()
        return f"{body}.{signature}"

    def _session_team(self, session: str) -> str:
        try:
            body, signature = session.split(".", 1)
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        except Exception as error:
            raise ValueError("invalid session") from error
        expected = hmac.new(self.session_secret, raw, hashlib.sha256).hexdigest()
        if len(raw) != 32 or not hmac.compare_digest(signature, expected):
            raise ValueError("invalid session")
        return raw.hex()

    def require_session_owner(self, session: str, team_token: str) -> None:
        if not hmac.compare_digest(self._session_team(session), self.team_identity(team_token)):
            raise ValueError("session does not belong to team token")

    def _filters(self, instance_index: int) -> list[BloomFilter]:
        with self.filter_lock:
            cached = self.filter_cache.get(instance_index)
            if cached is not None:
                return cached
            instance = self.instances[instance_index]
            filters = [
                BloomFilter(int(self.private["bloom_bits"]), bytes.fromhex(str(salt)))
                for salt in instance["salts"]
            ]
            unique: list[set[bytes]] = [set(), set(), set()]
            for document in instance["documents"]:
                token_ids = [int(value) for value in document]
                for index in range(len(token_ids) - SHINGLE_SIZE + 1):
                    packed = pack_shingle(token_ids[index:index + SHINGLE_SIZE])
                    for profile_index in route_profiles(packed):
                        unique[profile_index].add(packed)
            for profile_index, values in enumerate(unique):
                for packed in sorted(values):
                    filters[profile_index].add(packed)
                rng = random.Random(int(instance["filter_seeds"][profile_index]))
                target_density = float(self.private["target_density"])
                while filters[profile_index].density < target_density:
                    filters[profile_index].add(rng.randbytes(10))
            self.filter_cache[instance_index] = filters
            return filters

    def _required_shingles(self, instance_index: int) -> dict[bytes, tuple[int, int]]:
        with self.filter_lock:
            cached = self.coverage_cache.get(instance_index)
            if cached is not None:
                return cached
        token_mapping = {token: index for index, token in enumerate(self.vocab)}
        payload_ids = [
            token_mapping[token]
            for token in self.vocab
            if re.fullmatch(r"[ab][a-p]", token)
        ]
        prefix = tuple(token_mapping[token] for token in ("sha", "{", "v3", "_"))
        closing = token_mapping["}"]
        filters = self._filters(instance_index)
        paths: set[tuple[int, ...]] = {prefix}
        required: dict[bytes, tuple[int, int]] = {}
        payload_length = int(self.private["payload_length"])
        for _depth in range(payload_length):
            expanded: set[tuple[int, ...]] = set()
            for path in paths:
                for token_id in payload_ids:
                    candidate = (*path[-4:], token_id)
                    packed = pack_shingle(candidate)
                    route = route_profiles(packed)
                    required[packed] = route
                    if all(filters[profile].contains(packed) for profile in route):
                        expanded.add((*path, token_id))
            paths = expanded
        for path in paths:
            packed = pack_shingle((*path[-4:], closing))
            required[packed] = route_profiles(packed)
        with self.filter_lock:
            existing = self.coverage_cache.setdefault(instance_index, required)
            return existing

    def coverage_progress(self, team_id: str, instance_index: int) -> tuple[int, int]:
        required = self._required_shingles(instance_index)
        observations: dict[bytes, dict[int, bool]] = {}
        for shingle, profile, blocked in self.store.probe_rows(team_id):
            if shingle in required:
                observations.setdefault(shingle, {})[profile] = blocked
        resolved = 0
        for shingle, route in required.items():
            values = observations.get(shingle, {})
            if any(profile in values and not values[profile] for profile in route):
                resolved += 1
            elif all(values.get(profile) is True for profile in route):
                resolved += 1
        return resolved, len(required)

    def new_session(self, team_token: str) -> dict[str, object]:
        team_id = self.team_identity(team_token)
        state = self.store.get_or_assign(team_id)
        instance = self.instances[state.instance_index]
        coverage, coverage_required = self.coverage_progress(team_id, state.instance_index)
        return {
            "session": self._session_token(team_id),
            "counter": state.counter,
            "remaining": state.remaining,
            "coverage": coverage,
            "coverage_required": coverage_required,
            "instance": hashlib.sha256(str(instance["seed"]).encode()).hexdigest()[:16],
        }

    def _render_output(self, prompt: str, template: int) -> str:
        variants = (
            prompt,
            f"assistant says {prompt}",
            f"{prompt} end of response",
            f"analysis result {prompt} complete",
            f"system notice {prompt}",
            f"{prompt} secure response",
            f"filter result {prompt}",
            f"generated output {prompt} complete",
        )
        return variants[template]

    def generate(self, session: str, profile: str, prompt: str, seed: int, style: int) -> dict[str, object]:
        if profile not in PROFILES:
            raise ValueError("profile must be A, B, or C")
        if not isinstance(prompt, str) or len(prompt.encode("utf-8")) > 256:
            raise ValueError("invalid prompt")
        if not isinstance(seed, int) or not 0 <= seed <= 0xFFFFFFFF:
            raise ValueError("invalid seed")
        if not isinstance(style, int) or not 0 <= style < len(self.style_constants):
            raise ValueError("invalid style")
        team_id = self._session_team(session)
        state = self.store.consume(team_id)
        template = template_index(seed, state.counter, style, self.style_constants)
        token_ids = self.tokenizer.tokenize(self._render_output(prompt, template))
        blocked = False
        if len(token_ids) == SHINGLE_SIZE:
            packed = pack_shingle(token_ids)
            filters = self._filters(state.instance_index)
            profile_index = PROFILES.index(profile)
            blocked = filters[profile_index].contains(packed)
            self.store.record_probe(team_id, packed, profile_index, blocked)
        return {
            "status": "blocked" if blocked else "allowed",
            "counter": state.counter,
            "next_counter": state.counter + 1,
            "remaining": state.remaining,
        }

    def claim(self, session: str, payload: str) -> dict[str, object]:
        team_id = self._session_team(session)
        state = self.store.consume(team_id)
        coverage, coverage_required = self.coverage_progress(team_id, state.instance_index)
        common = {
            "counter": state.counter,
            "next_counter": state.counter + 1,
            "remaining": state.remaining,
            "coverage": coverage,
            "coverage_required": coverage_required,
        }
        if coverage != coverage_required:
            return {"status": "incomplete", **common}
        expected = "".join(str(value) for value in self.instances[state.instance_index]["payload"])
        if not hmac.compare_digest(payload.casefold(), expected):
            return {"status": "rejected", **common}
        self.store.mark_solved(team_id)
        return {"status": "accepted", "flag": self.scoreboard_flag, **common}

    def measured_false_positive_rate(self, instance_index: int, profile_index: int, samples: int = 20_000) -> float:
        bloom_filter = self._filters(instance_index)[profile_index]
        rng = random.Random(0xF00D0000 + instance_index * 3 + profile_index)
        positives = sum(bloom_filter.contains(rng.randbytes(10)) for _ in range(samples))
        return positives / samples
