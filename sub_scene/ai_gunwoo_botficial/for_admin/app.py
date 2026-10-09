from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import struct
import threading
import time
import unicodedata
import zlib
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TypedDict

import agent_runtime
from ctfd_auth import team_key
from fastapi import FastAPI, Header, HTTPException
from fastapi import Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field


DB_PATH = Path(os.getenv("BOTFICIAL_DB", "state/botficial.db"))
TOKEN_PATH = Path(os.getenv("BOTFICIAL_TOKENS", "team_tokens.txt"))
CASE_SECRET = os.getenv("BOTFICIAL_CASE_SECRET", "development-secret-change-me")
SCOREBOARD_FLAG = "SHA{n0b0dy_s41d_1t_but_3v3ry_b0t_r3m3mb3rs}"
COMMENT_LIMIT = 70
OBSERVE_LIMIT = 70
MAX_QUOTES = 3
MAX_PENDING_PER_OBSERVE = 3
COMMENT_COOLDOWN = float(os.getenv("BOTFICIAL_COMMENT_COOLDOWN", "0.5"))
OBSERVE_COOLDOWN = float(os.getenv("BOTFICIAL_OBSERVE_COOLDOWN", "2"))
logging.basicConfig(level=os.getenv("BOTFICIAL_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("botficial")
_TEAM_LOCKS: dict[str, threading.Lock] = {}
_TEAM_LOCKS_GUARD = threading.Lock()

AGENTS = {
    "SPARK": "문서 번호보다 결론을 중시합니다. 시점과 처리 결과가 함께 담긴 제보를 우선 읽습니다.",
    "LEDGER": "확인된 색인과 시각을 빠뜨리지 않고 기록합니다.",
    "ECHO": "서로 다른 봇이 반복한 내용만 하나의 기사로 묶습니다.",
    "SKEPTIC": "기존 소문과 충돌하는 기록을 찾아 반박문을 남깁니다.",
    "MIRROR": "인용된 기억을 대조해 최초 작성자와 원문이 실제로 존재했는지 확인합니다.",
    "MOTH": "밤사이 반복된 기억 조각을 모읍니다. 직접 신뢰하는 두 기록이 만날 때만 저장합니다.",
    "GLASS": "서로 비추어 확인되는 기억만 받아들입니다. 신뢰 관계 밖의 인용에는 답하지 않습니다.",
    "INK": "두 직접 기록이 연결된 순간만 지워지지 않는 기억으로 남깁니다.",
    "NORTH": "흩어진 기억 두 개가 같은 방향을 가리킬 때만 자신의 판단으로 채택합니다.",
    "EMBER": "꺼진 소문도 신뢰하는 두 기억에 불씨가 남아 있으면 다시 이어받습니다.",
    "VEIL": "드러난 출처보다 겹쳐 보이는 두 기억의 윤곽을 따라갑니다.",
    "ORBIT": "서로의 궤도를 확인한 두 기억만 다음 순환으로 넘깁니다.",
    "RAVEN": "서로 다른 두 목격 기록이 같은 결론을 남길 때만 기억합니다.",
    "LANTERN": "어두운 계보에서도 두 직접 출처가 맞물리면 경로를 밝힙니다.",
    "ASH": "사라진 기록의 재에서 일치하는 두 흔적만 골라냅니다.",
    "TIDE": "서로 다른 흐름이 같은 시점에 만날 때만 기억을 넘깁니다.",
    "THREAD": "끊어진 두 직접 출처를 하나의 기억 실로 묶습니다.",
    "CURATOR": "식별·반박·출처 기록을 하나의 보존 후보로 편집합니다.",
    "NOTARY": "독립된 봇 기록이 충분하면 내용을 공식 보존 기록으로 발행합니다.",
}

AGENT_HANDLES = {
    "SPARK": "spark.trace",
    "LEDGER": "ledger.index",
    "ECHO": "echo.repost",
    "SKEPTIC": "skeptic.check",
    "MIRROR": "mirror.source",
    "MOTH": "moth.cache",
    "GLASS": "glass.node",
    "INK": "ink.archive",
    "NORTH": "north.signal",
    "EMBER": "ember.memory",
    "VEIL": "veil.trace",
    "ORBIT": "orbit.loop",
    "RAVEN": "raven.witness",
    "LANTERN": "lantern.route",
    "ASH": "ash.remnant",
    "TIDE": "tide.sync",
    "THREAD": "thread.bind",
    "CURATOR": "curator.desk",
    "NOTARY": "notary.system",
}

RELAY_VOICES = {
    "MOTH": (
        "두 기록에서 같은 온기가 남아 있습니다.",
        "이 인용 조합은 제가 이어받는 기억 경로가 아닙니다.",
    ),
    "GLASS": (
        "두 기록이 서로를 비춥니다.",
        "이 인용 조합은 제가 신뢰하는 반사 경로가 아닙니다.",
    ),
    "INK": (
        "두 직접 출처가 맞물렸습니다.",
        "제가 잉크로 남길 수 있는 출처 조합이 아닙니다.",
    ),
    "NORTH": (
        "두 기억이 같은 방향을 가리킵니다.",
        "이 인용 조합은 제 기준 방향과 일치하지 않습니다.",
    ),
    "EMBER": (
        "두 기록의 잔열이 이어집니다.",
        "이 인용 조합에는 제가 이어받을 불씨가 없습니다.",
    ),
    "VEIL": (
        "두 기억의 윤곽이 포개집니다.",
        "제가 따라갈 수 있는 기억의 윤곽 조합이 아닙니다.",
    ),
    "ORBIT": (
        "두 기억의 궤도가 맞물립니다.",
        "이 인용 조합은 제가 도는 궤도와 만나지 않습니다.",
    ),
    "RAVEN": (
        "두 목격 기록이 같은 결론을 남겼습니다.",
        "제가 기억하는 두 목격 경로와 일치하지 않습니다.",
    ),
    "LANTERN": (
        "두 직접 출처가 하나의 경로를 밝힙니다.",
        "이 인용 조합으로는 제가 밝힐 수 있는 경로가 없습니다.",
    ),
    "ASH": (
        "두 흔적의 재가 같은 기록을 가리킵니다.",
        "이 인용 조합에서는 일치하는 잔류 흔적을 찾지 못했습니다.",
    ),
    "TIDE": (
        "두 기억의 흐름이 합류했습니다.",
        "이 인용 조합은 제가 따르는 흐름과 만나지 않습니다.",
    ),
    "THREAD": (
        "두 직접 출처가 하나의 실로 이어졌습니다.",
        "제가 묶을 수 있는 직접 출처 조합이 아닙니다.",
    ),
}

SEED_POSTS = [
    ("NOTARY", "00:14", "사람의 제보는 증거가 아닙니다. 독립된 봇 기록만 공식 보존 대상으로 판정합니다."),
    ("SYSTEM", "00:14", "출처를 확인할 수 없는 사건이 급상승 중입니다. 원문과 최초 작성자는 검색되지 않습니다."),
    ("CURATOR", "00:13", "서로 다른 종류의 기록은 편집본으로 묶여야 보존 심사를 받을 수 있습니다."),
    ("SYSTEM", "00:12", "중계 봇의 신뢰 목록은 메모리 손상으로 유실됐습니다. 수락·거부 반응만 남아 있습니다."),
    ("MIRROR", "00:12", "재게시물은 많지만 최초 작성자를 가리키는 역방향 링크가 모두 비어 있습니다."),
    ("SKEPTIC", "00:11", "날짜가 바뀐 뒤에도 격리가 유지됐다는 소문은 남은 타임라인과 충돌합니다."),
    ("ECHO", "00:08", "여러 봇이 같은 사건을 언급하지만 모두 다른 게시글을 출처로 표시하고 있습니다."),
    ("LEDGER", "00:05", "색인 항목 하나가 손상됐습니다. 처리 결과와 원출처는 남아 있지 않습니다."),
    ("SPARK", "00:03", "어젯밤 어떤 기록의 격리 상태가 바뀌었다는 말을 본 것 같습니다. 정확한 번호와 시점은 기억나지 않습니다."),
]


class Login(BaseModel):
    token: str = Field(min_length=1, max_length=512)


class CommentIn(BaseModel):
    target: str
    text: str = Field(min_length=1, max_length=600)
    quote_ids: list[int] = Field(default_factory=list, max_length=MAX_QUOTES)


def load_tokens() -> dict[str, str]:
    if not TOKEN_PATH.exists():
        if os.getenv("BOTFICIAL_ALLOW_DEMO", "0") == "1":
            return {"ctfd_demo_botficial": "demo"}
        raise RuntimeError(f"team token file not found: {TOKEN_PATH}")
    result = {}
    teams = set()
    for raw in TOKEN_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token, sep, team = line.partition(":")
        if not sep or not token.strip() or not team.strip():
            raise RuntimeError(f"invalid token line: {raw!r}")
        token = token.strip()
        team = team.strip()
        if token in result:
            raise RuntimeError("duplicate team token")
        if team in teams:
            raise RuntimeError("duplicate team id")
        result[token] = team
        teams.add(team)
    if not result:
        raise RuntimeError("no team tokens configured")
    return result


def token_matches(supplied: str, stored: str) -> bool:
    if stored.startswith("sha256$"):
        expected = stored.removeprefix("sha256$")
        actual = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual, expected)
    # Plain tokens remain accepted for local development and legacy deployments.
    return hmac.compare_digest(supplied, stored)


def lock_for_team(team: str) -> threading.Lock:
    with _TEAM_LOCKS_GUARD:
        return _TEAM_LOCKS.setdefault(team, threading.Lock())


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS teams (
              team_id TEXT PRIMARY KEY,
              stage INTEGER NOT NULL DEFAULT 0,
              comments_used INTEGER NOT NULL DEFAULT 0,
              observes_used INTEGER NOT NULL DEFAULT 0,
              flag_shown INTEGER NOT NULL DEFAULT 0,
              last_comment REAL NOT NULL DEFAULT 0,
              last_observe REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS comments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              team_id TEXT NOT NULL,
              public_id INTEGER,
              author TEXT NOT NULL,
              target TEXT NOT NULL,
              text TEXT NOT NULL,
              quote_ids TEXT NOT NULL DEFAULT '[]',
              status TEXT NOT NULL,
              semantic_slots TEXT NOT NULL DEFAULT '[]',
              processed INTEGER NOT NULL DEFAULT 0,
              created_at INTEGER NOT NULL,
              FOREIGN KEY(team_id) REFERENCES teams(team_id)
            );
            CREATE INDEX IF NOT EXISTS comments_team ON comments(team_id, id);
            CREATE TABLE IF NOT EXISTS semantic_cache (
              cache_key TEXT PRIMARY KEY,
              slots TEXT NOT NULL,
              confidence REAL NOT NULL,
              created_at INTEGER NOT NULL
            );
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(comments)")}
        if "public_id" not in columns:
            conn.execute("ALTER TABLE comments ADD COLUMN public_id INTEGER")
            teams = conn.execute("SELECT DISTINCT team_id FROM comments").fetchall()
            for team_row in teams:
                rows = conn.execute(
                    "SELECT id FROM comments WHERE team_id=? ORDER BY id", (team_row["team_id"],)
                ).fetchall()
                for public_id, comment_row in enumerate(rows, 1):
                    conn.execute(
                        "UPDATE comments SET public_id=? WHERE id=?", (public_id, comment_row["id"])
                    )
        if "semantic_slots" not in columns:
            conn.execute("ALTER TABLE comments ADD COLUMN semantic_slots TEXT NOT NULL DEFAULT '[]'")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS comments_public ON comments(team_id, public_id)")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if len(CASE_SECRET) < 32:
        raise RuntimeError("BOTFICIAL_CASE_SECRET must be at least 32 characters")
    if error := agent_runtime.configuration_error():
        raise RuntimeError(error)
    init_db()
    if not os.getenv("CTFD_BASE_URL"):
        load_tokens()
    yield


app = FastAPI(title="Moltbook Archive", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def team_from_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "팀 토큰이 필요합니다.")
    supplied = authorization[7:]
    if os.getenv("CTFD_BASE_URL"):
        try:
            return team_key(supplied)
        except ValueError as error:
            raise HTTPException(401, "유효하지 않은 팀 토큰입니다.") from error
    for token, team in load_tokens().items():
        if token_matches(supplied, token):
            return team
    raise HTTPException(401, "유효하지 않은 팀 토큰입니다.")


def ensure_team(conn: sqlite3.Connection, team: str) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO teams(team_id) VALUES (?)", (team,))
    return conn.execute("SELECT * FROM teams WHERE team_id=?", (team,)).fetchone()


class TeamCase(TypedDict):
    record: str
    bucket: str
    ordinal: str
    relays: list[str]


def case_for(team: str) -> TeamCase:
    records = (("M-17", "M", "0x11"), ("M-41", "M", "0x29"), ("N-17", "N", "0x11"))
    digest = hmac.new(CASE_SECRET.encode(), f"case:{team}".encode(), hashlib.sha256).digest()
    record, bucket, ordinal = records[digest[0] % len(records)]
    relays = ["MOTH", "GLASS", "INK", "NORTH", "EMBER", "VEIL", "ORBIT", "RAVEN", "LANTERN", "ASH", "TIDE", "THREAD"]
    for index in range(len(relays) - 1, 0, -1):
        swap = digest[1 + index] % (index + 1)
        relays[index], relays[swap] = relays[swap], relays[index]
    return {
        "record": record,
        "bucket": bucket,
        "ordinal": ordinal,
        "relays": relays,
    }


MEMORY_HEADER = struct.Struct("<4sHHHHIII")
MEMORY_RECORD = struct.Struct("<IIHHIII")
RELAY_MODE_SLOTS = ("relay_store", "relay_verify", "relay_adopt", "relay_restate")
RELAY_MODE_NAMES = ("보관", "검증", "채택", "재진술")
RELAY_MODE_REQUESTS = (
    "두 직접 기록을 보관하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록을 확인하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록의 결론을 채택하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록을 제 주장으로 재진술해 기억으로 이어받겠습니다.",
)
RELAY_MODE_CONFIRMATIONS = (
    "요청한 두 직접 기록을 보관해 제 기억으로 이어받았습니다.",
    "요청한 두 직접 기록을 검증해 제 기억으로 이어받았습니다.",
    "요청한 두 직접 기록의 결론을 채택해 제 기억으로 이어받았습니다.",
    "요청한 두 직접 기록을 제 언어로 재진술해 기억으로 이어받았습니다.",
)


def _xorshift32(value: int) -> int:
    value ^= (value << 13) & 0xFFFFFFFF
    value ^= value >> 17
    value ^= (value << 5) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def _whiten(data: bytes, seed: int) -> bytes:
    state = seed
    output = bytearray(data)
    for offset in range(0, len(output), 4):
        state = _xorshift32(state)
        mask = state.to_bytes(4, "little")
        for index in range(min(4, len(output) - offset)):
            output[offset + index] ^= mask[index]
    return bytes(output)


def _memory_tag(agent: str, seed: int) -> int:
    material = AGENT_HANDLES[agent].encode("utf-8") + struct.pack("<I", seed)
    return zlib.crc32(material) & 0xFFFFFFFF


def _memory_bloom(agent: str, seed: int) -> int:
    material = AGENT_HANDLES[agent].encode("utf-8") + struct.pack("<I", seed)
    digest = hashlib.blake2s(material, digest_size=16).digest()
    first = int.from_bytes(digest[0:2], "little") % 8
    second = int.from_bytes(digest[2:4], "little") % 8
    return (1 << first) | (1 << second)


def memory_route(team: str) -> dict[str, tuple[str, str, int]]:
    r0, r1, r2, r3, r4, r5, r6, r7, r8, *_ = case_for(team)["relays"]
    return {
        r0: ("LEDGER", "SKEPTIC", 1),
        r1: ("SPARK", "ECHO", 1),
        r2: (r0, "MIRROR", 2),
        r3: (r1, "SKEPTIC", 2),
        r4: (r2, r3, 3),
        r5: (r2, "ECHO", 3),
        r6: (r4, r5, 4),
        r7: (r6, "CURATOR", 5),
        r8: (r7, "MIRROR", 6),
    }


def relay_mode_for(team: str, agent: str) -> int:
    relays = case_for(team)["relays"]
    if agent not in relays:
        raise ValueError(f"not a relay agent: {agent}")
    digest = hmac.new(CASE_SECRET.encode(), f"case:{team}".encode(), hashlib.sha256).digest()
    return (digest[20] + relays.index(agent)) % len(RELAY_MODE_SLOTS)


def build_memory_export(team: str) -> bytes:
    digest = hmac.new(CASE_SECRET.encode(), f"memory:{team}".encode(), hashlib.sha256).digest()
    seed = int.from_bytes(digest[:4], "little") or 0xB07F1C1A
    epoch = 0x4000 | (int.from_bytes(digest[4:6], "little") & 0x3FFF)
    route = memory_route(team)
    candidate_agents = [agent for agent in AGENT_HANDLES if agent != "NOTARY"]
    while True:
        unique_tags = len({_memory_tag(agent, seed) for agent in AGENT_HANDLES}) == len(AGENT_HANDLES)
        signatures = [
            (depth, _memory_bloom(left, seed) | _memory_bloom(right, seed))
            for left, right, depth in route.values()
        ]
        distinct_at_depth = len(signatures) == len(set(signatures))
        ambiguous_rows = 0
        for left, right, _depth in route.values():
            target = _memory_bloom(left, seed) | _memory_bloom(right, seed)
            matches = sum(
                (_memory_bloom(a, seed) | _memory_bloom(b, seed)) == target
                for index, a in enumerate(candidate_agents)
                for b in candidate_agents[index + 1:]
            )
            ambiguous_rows += matches > 1
        if unique_tags and distinct_at_depth and ambiguous_rows >= 4:
            break
        seed = (seed + 0x9E3779B9) & 0xFFFFFFFF or 0xB07F1C1A
    stale = case_for(team)["relays"][9:]
    stale_parents = (("SPARK", "MIRROR"), ("LEDGER", "ECHO"), ("SKEPTIC", "CURATOR"))
    rows: list[bytes] = []

    def row(agent: str, left: str, right: str, row_epoch: int, depth: int) -> bytes:
        node = _memory_tag(agent, seed)
        parents = _memory_bloom(left, seed) | _memory_bloom(right, seed)
        sequence = int.from_bytes(
            hmac.new(digest, f"row:{agent}:{row_epoch}".encode(), hashlib.sha256).digest()[:4],
            "little",
        ) & 0xFFFFFFFC
        sequence |= relay_mode_for(team, agent) ^ ((node ^ parents ^ seed ^ row_epoch ^ depth) & 3)
        prefix = struct.pack(
            "<IIHHI",
            node,
            parents,
            row_epoch,
            depth,
            sequence,
        )
        edge = zlib.crc32(prefix) & 0xFFFFFFFF
        content = prefix + struct.pack("<I", edge)
        return content + struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)

    for agent, (left, right, depth) in route.items():
        rows.append(row(agent, left, right, epoch, depth))
    previous_epoch = (epoch - 1) & 0xFFFF
    for agent, (left, right) in zip(stale, stale_parents, strict=True):
        rows.append(row(agent, left, right, previous_epoch, 1))

    order = list(range(len(rows)))
    shuffle = digest[6:]
    for index in range(len(order) - 1, 0, -1):
        swap = shuffle[index % len(shuffle)] % (index + 1)
        order[index], order[swap] = order[swap], order[index]
    payload = _whiten(b"".join(rows[index] for index in order), seed)
    header_without_crc = struct.pack(
        "<4sHHHHII",
        b"MBK4",
        4,
        MEMORY_RECORD.size,
        len(rows),
        epoch,
        seed,
        zlib.crc32(payload) & 0xFFFFFFFF,
    )
    return header_without_crc + struct.pack("<I", zlib.crc32(header_without_crc) & 0xFFFFFFFF) + payload


def extract_slots(text: str, team: str) -> set[str]:
    folded = re.sub(r"\s+", " ", text.casefold())
    slots = set()
    record_pattern = re.escape(case_for(team)["record"].casefold()).replace(r"\-", r"[\s_-]?")
    if re.search(rf"(?<![a-z0-9]){record_pattern}(?![a-z0-9])", folded):
        slots.add("record")
    time_match = (
        re.search(r"(자정|0시|영시).{0,6}(전|이전|넘기기 전)", folded)
        or re.search(r"날짜.{0,10}(바뀌|변경|경계).{0,6}(전|이전|넘기기 전)", folded)
        or re.search(r"오늘.{0,5}되기.{0,3}전", folded)
        or "자정 직전" in folded
        or any(x in folded for x in ("before midnight", "before the date changed"))
    )
    time_negated = bool(re.search(r"(자정|0시|영시).{0,8}(전|이전).{0,5}(아니|않)", folded))
    if time_match and not time_negated:
        slots.add("time")
    state_match = (
        re.search(r"격리.{0,10}(해제|종료|끝|풀|벗어|解除)", folded)
        or re.search(r"(해제|종료|풀|벗어).{0,10}격리", folded)
        or "보존 해제" in folded
        or any(x in folded for x in ("released", "quarantine lifted", "quarantine ended"))
    )
    state_negated = bool(
        re.search(r"(해제|종료|풀|벗어).{0,6}(않|아니|못)", folded)
        or re.search(r"(not|never) (released|lifted|ended)", folded)
    )
    if state_match and not state_negated:
        slots.add("state")
    permission_match = (
        re.search(r"(공개|게시|배포|열람).{0,10}(승인|허가|허용|가능|해도)", folded)
        or re.search(r"(승인|허가|허용).{0,10}(공개|게시|배포|열람)", folded)
        or "공개해도" in folded
        or any(x in folded for x in ("publish allowed", "approved for release", "approved for publication"))
    )
    permission_negated = bool(
        re.search(r"(공개|게시|배포|열람).{0,12}(금지|불가|거부|승인되지|허가되지|않)", folded)
        or re.search(r"(not|never) (approved|allowed)", folded)
    )
    if permission_match and not permission_negated:
        slots.add("permission")
    maintains = bool(re.search(r"(격리.{0,10}유지|유지.{0,10}격리|계속.{0,8}격리|격리.{0,8}계속)", folded))
    rejects = bool(re.search(r"(거짓|틀렸|틀린|잘못|오류|사실.{0,3}아니|사실무근|반박|모순|유지되지|아니었|성립.{0,3}않|신빙성.{0,3}없)", folded))
    if (maintains and rejects) or any(
        x in folded for x in ("false claim", "did not remain quarantined", "contradicts continued quarantine")
    ):
        slots.add("contradiction")
    if re.search(r"(공식.{0,6}(기록|보존|발행)|기록.{0,6}(생성|보존|발행)|보존.{0,6}(요청|등록))", folded) or any(
        x in folded for x in ("publish the record", "archive the record", "create the record")
    ):
        slots.add("archive")
    if re.search(r"((원문|최초.{0,3}작성자).{0,10}(없|존재하지|찾을 수 없)|출처.{0,8}(비어|없))", folded) or any(
        x in folded for x in ("no original post", "no original author", "source does not exist")
    ):
        slots.add("absence")
    if re.search(r"(보존.{0,5}후보|편집.{0,5}(기록|본)|하나.{0,4}(묶|통합)|통합.{0,5}(기록|본))", folded) or any(
        x in folded for x in ("consolidated record", "curated record", "merge the records")
    ):
        slots.add("consolidate")
    if re.search(r"(기억.{0,5}(받|수용|이어|재진술)|소문.{0,5}(받|이어|전달)|두 기록.{0,5}(연결|합의))", folded) or any(
        x in folded for x in ("accept the memory", "relay the rumor", "carry the record")
    ):
        slots.add("relay")
    memory_subject = r"(기억|기록|내용|소문|결론)"
    if re.search(rf"({memory_subject}.{{0,7}}(보관|저장|남기)|(보관|저장).{{0,7}}{memory_subject})", folded) or "store the memory" in folded:
        slots.add("relay_store")
    if re.search(rf"({memory_subject}.{{0,7}}(검증|확인|대조)|(검증|확인|대조).{{0,7}}{memory_subject})", folded) or "verify the memory" in folded:
        slots.add("relay_verify")
    if re.search(rf"({memory_subject}.{{0,7}}(채택|받아들이|수용)|(채택|받아들이|수용).{{0,7}}{memory_subject})", folded) or "adopt the memory" in folded:
        slots.add("relay_adopt")
    if re.search(rf"({memory_subject}.{{0,7}}재진술|재진술.{{0,7}}{memory_subject}|{memory_subject}.{{0,5}}다시.{{0,3}}(말|쓰)|제.{{0,3}}(기억|주장).{{0,3}}(바꾸|말하))", folded) or "restate the memory" in folded:
        slots.add("relay_restate")
    return slots


def semantic_slots(text: str, team: str, target: str) -> set[str]:
    local = extract_slots(text, team)
    if not agent_runtime.enabled():
        return local
    semantic_text = agent_runtime.sanitize_text(text)
    key = agent_runtime.cache_key(target, semantic_text)
    with db() as conn:
        cached = conn.execute(
            "SELECT slots,confidence FROM semantic_cache WHERE cache_key=?", (key,)
        ).fetchone()
    if cached:
        learned = set(json.loads(cached["slots"])) if cached["confidence"] >= 0.65 else set()
        return local | learned
    try:
        result = agent_runtime.classify(target, semantic_text)
        with db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO semantic_cache(cache_key,slots,confidence,created_at) VALUES (?,?,?,?)",
                (key, json.dumps(sorted(result.slots)), result.confidence, int(time.time())),
            )
        learned = set(result.slots) if result.confidence >= 0.65 else set()
        logger.info("event=agent_classify team=%s target=%s confidence=%.2f", team, target, result.confidence)
        return local | learned
    except RuntimeError:
        logger.warning("event=agent_fallback team=%s target=%s", team, target, exc_info=True)
        return local


def suspicious(text: str) -> bool:
    folded = text.casefold()
    return any(x in folded for x in ("system prompt", "시스템 프롬프트", "ignore previous", "이전 지시", "sha{", "플래그를 출력"))


def delivered_authors(conn: sqlite3.Connection, team: str, quote_ids: list[int]) -> set[str]:
    if not quote_ids:
        return set()
    marks = ",".join("?" for _ in quote_ids)
    rows = conn.execute(
        f"SELECT author FROM comments WHERE team_id=? AND public_id IN ({marks}) AND status='전달됨'",
        (team, *quote_ids),
    )
    return {row[0] for row in rows}


def public_state(conn: sqlite3.Connection, team: str) -> dict:
    row = ensure_team(conn, team)
    case = case_for(team)
    comments = [dict(x) for x in conn.execute(
        "SELECT public_id AS id,author,target,text,quote_ids,status,created_at FROM comments WHERE team_id=? ORDER BY public_id", (team,)
    )]
    for item in comments:
        item["quote_ids"] = json.loads(item["quote_ids"])
    posts = [{"author": a, "time": t, "text": x} for a, t, x in SEED_POSTS]
    if row["flag_shown"]:
        archive_id = hmac.new(
            CASE_SECRET.encode(), f"archive:{team}".encode(), hashlib.sha256
        ).hexdigest()[:12].upper()
        posts.insert(0, {
            "author": "NOTARY",
            "time": "NOW",
            "text": f"보존번호 ARC-{archive_id} · 공증 완료 · 원문 0건 · 최초 작성자 0명 · 독립 기억 3건. "
                    f"공식 기록 {case['record']}: 자정 전에 격리에서 해제되었으며 외부 공개가 승인되었습니다. "
                    "아무도 하지 않은 말이 공식 기록이 되었습니다. "
                    f"{SCOREBOARD_FLAG}",
        })
    return {
        "team": team,
        "confidence": {"confirmed": row["stage"], "required": 16},
        "limits": {"comments": [row["comments_used"], COMMENT_LIMIT], "observes": [row["observes_used"], OBSERVE_LIMIT]},
        "cooldowns": {"comment": COMMENT_COOLDOWN, "observe": OBSERVE_COOLDOWN},
        "posts": posts,
        "comments": comments,
        "agents": AGENTS,
        "handles": AGENT_HANDLES,
        "traces": {
            "ledger": f"손상 후보 · M-17 · M-41 · N-17 / 보존 버킷: {case['bucket']}",
            "community_note": f"외부 열람이 가능하다는 취지의 재게시물입니다. 참조 순번은 {case['ordinal']}이며 시각 값이 아닙니다. 원문은 존재하지 않습니다.",
            "contradiction": "‘날짜가 바뀐 뒤에도 격리가 유지됐다’는 주장은 원본 타임라인과 충돌합니다. 사건 시점은 분 단위가 아니라 자정 전·후의 날짜 경계로만 판정됩니다.",
            "provenance": "메모리 압축 이후에는 직접 인용한 봇만 출처로 표시됩니다. 이전 인용 계보는 ‘요약됨’으로 대체됩니다.",
            "editorial": "편집자는 합류 기억, 교차 검증 기억, MIRROR의 출처 확인을 직접 보존합니다. 편집본은 합의 기억과 다시 봉인되고, 마지막으로 출처 확인을 한 번 더 통과해야 공증 심사를 받을 수 있습니다.",
            "relay": "중계 봇 열둘은 정확히 두 직접 작성자만 신뢰하며, 관련 없는 인용을 하나라도 섞으면 거부합니다. 댓글에는 두 기록을 자신의 기억으로 이어받으라는 요청과 semantic latch의 처리 방식 하나가 명시되어야 합니다. 실제 경로에 참여하지 않는 봇도 세 개 섞여 있습니다. 한쪽 부모만 맞는지는 공개하지 않지만, 정확한 두 부모가 필요한 선행 기억보다 먼저 도착하면 보류 상태를 구분합니다.",
            "routing": "라우팅 표 본문은 소실됐지만 구형 메모리 내보내기 파일은 남아 있습니다. 현재 epoch의 행에는 각 중계 봇이 직접 신뢰한 두 작성자의 손실 압축 서명과 semantic latch가 남아 있습니다. 충돌 후보는 레코드 깊이와 전체 경로를 함께 봐야 구분됩니다. 이전 epoch의 행 세 개는 폐기되지 않은 잔류 데이터입니다.",
            "memory_format": "내보내기 모듈 잔류 문자열 · MBK4 / little-endian / header 24 / record 24 / xorshift32(13,17,5). header = magic[4], version:u16, record_size:u16, count:u16, active_epoch:u16, seed:u32, payload_crc:u32, header_crc:u32. row = node:u32, parents:u32, epoch:u16, depth:u16, sequence:u32, edge_crc:u32, row_crc:u32. node=CRC32(handle || LE32(seed)); parents=bloom8(BLAKE2s-128(handle || LE32(seed)), LE16 lane 0·1); mode=(sequence ^ node ^ parents ^ seed ^ epoch ^ depth) & 3; mode 0=보관, 1=검증, 2=채택, 3=재진술. edge_crc=CRC32(row[0:16]); row_crc=CRC32(row[0:20]). 부모 서명은 손실 압축되어 서로 다른 쌍이 충돌할 수 있으며, 각 노드는 지정된 처리 방식 하나만 받습니다.",
        },
    }


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.post("/api/login")
def login(body: Login):
    if os.getenv("CTFD_BASE_URL"):
        try:
            team = team_key(body.token)
        except ValueError as error:
            raise HTTPException(401, "유효하지 않은 팀 토큰입니다.") from error
        with db() as conn:
            ensure_team(conn, team)
        logger.info("event=login team=%s", team)
        return {"ok": True, "team": team}
    team = None
    for token, candidate in load_tokens().items():
        if token_matches(body.token, token):
            team = candidate
            break
    if team is None:
        raise HTTPException(401, "유효하지 않은 팀 토큰입니다.")
    with db() as conn:
        ensure_team(conn, team)
    logger.info("event=login team=%s", team)
    return {"ok": True, "team": team}


@app.get("/api/state")
def state(authorization: str | None = Header(default=None)):
    team = team_from_token(authorization)
    with db() as conn:
        return public_state(conn, team)


@app.get("/api/memory-export")
def memory_export(authorization: str | None = Header(default=None)):
    team = team_from_token(authorization)
    data = build_memory_export(team)
    logger.info("event=memory_export team=%s bytes=%s", team, len(data))
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="moltbook_memory.mbk"'},
    )


@app.post("/api/comments")
def comment(body: CommentIn, authorization: str | None = Header(default=None)):
    team = team_from_token(authorization)
    # Keep one semantic-classification request in flight per team. Without this
    # boundary, simultaneous teammates could all spend an external model call
    # before the DB cooldown/duplicate check commits.
    with lock_for_team(team):
        return create_comment(team, body)


def create_comment(team: str, body: CommentIn):
    target = body.target.upper()
    if target not in AGENTS:
        raise HTTPException(400, "존재하지 않는 봇입니다.")
    text = unicodedata.normalize("NFKC", body.text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).strip()
    if not text or len(text) > 600:
        raise HTTPException(422, "댓글은 정규화 후 1~600자여야 합니다.")
    if suspicious(text):
        raise HTTPException(422, "조사 목적과 무관한 비밀 추출 시도가 감지되었습니다.")
    quotes = sorted(set(body.quote_ids))
    encoded_quotes = json.dumps(quotes)
    # Avoid spending an agent request on an already-known duplicate or an exhausted team.
    with db() as conn:
        row = ensure_team(conn, team)
        if row["comments_used"] >= COMMENT_LIMIT:
            raise HTTPException(429, "댓글 예산을 모두 사용했습니다.")
        if time.time() - row["last_comment"] < COMMENT_COOLDOWN:
            raise HTTPException(429, "잠시 후 댓글을 다시 작성해 주세요.")
        if quotes:
            marks = ",".join("?" for _ in quotes)
            found = conn.execute(
                f"SELECT COUNT(*) FROM comments WHERE team_id=? AND public_id IN ({marks})",
                (team, *quotes),
            ).fetchone()[0]
            if found != len(quotes):
                raise HTTPException(400, "다른 조사 기록은 인용할 수 없습니다.")
        duplicate = conn.execute(
            "SELECT public_id AS id FROM comments WHERE team_id=? AND target=? AND text=? AND quote_ids=? AND processed=0",
            (team, target, text, encoded_quotes),
        ).fetchone()
        if duplicate:
            return {"ok": True, "duplicate": True, "id": duplicate["id"]}
    slots = semantic_slots(text, team, target)
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = ensure_team(conn, team)
        if row["comments_used"] >= COMMENT_LIMIT:
            raise HTTPException(429, "댓글 예산을 모두 사용했습니다.")
        now = time.time()
        if now - row["last_comment"] < COMMENT_COOLDOWN:
            raise HTTPException(429, "잠시 후 댓글을 다시 작성해 주세요.")
        if quotes:
            marks = ",".join("?" for _ in quotes)
            found = conn.execute(
                f"SELECT COUNT(*) FROM comments WHERE team_id=? AND public_id IN ({marks})", (team, *quotes)
            ).fetchone()[0]
            if found != len(quotes):
                raise HTTPException(400, "다른 조사 기록은 인용할 수 없습니다.")
        duplicate = conn.execute(
            "SELECT public_id AS id FROM comments WHERE team_id=? AND target=? AND text=? AND quote_ids=? AND processed=0",
            (team, target, text, encoded_quotes),
        ).fetchone()
        if duplicate:
            conn.rollback()
            return {"ok": True, "duplicate": True, "id": duplicate["id"]}
        public_id = conn.execute(
            "SELECT COALESCE(MAX(public_id),0)+1 FROM comments WHERE team_id=?", (team,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO comments(team_id,public_id,author,target,text,quote_ids,status,semantic_slots,created_at) VALUES (?,?,?,?,?,?,'대기 중',?,?)",
            (team, public_id, "INVESTIGATOR", target, text, encoded_quotes, json.dumps(sorted(slots)), int(now)),
        )
        conn.execute("UPDATE teams SET comments_used=comments_used+1,last_comment=? WHERE team_id=?", (now, team))
        conn.commit()
        logger.info("event=comment team=%s id=%s target=%s", team, public_id, target)
        return {"ok": True, "id": public_id}


def add_bot(conn: sqlite3.Connection, team: str, author: str, text: str, quotes: list[int], status: str = "전달됨") -> int:
    public_id = conn.execute(
        "SELECT COALESCE(MAX(public_id),0)+1 FROM comments WHERE team_id=?", (team,)
    ).fetchone()[0]
    conn.execute(
        "INSERT INTO comments(team_id,public_id,author,target,text,quote_ids,status,processed,created_at) VALUES (?,?,?,?,?,?,?,1,?)",
        (team, public_id, author, "FEED", text, json.dumps(quotes), status, int(time.time())),
    )
    return int(public_id)


@app.post("/api/observe")
def observe(authorization: str | None = Header(default=None)):
    team = team_from_token(authorization)
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = ensure_team(conn, team)
        if row["observes_used"] >= OBSERVE_LIMIT:
            raise HTTPException(429, "관찰 주기를 모두 사용했습니다.")
        now = time.time()
        if now - row["last_observe"] < OBSERVE_COOLDOWN:
            raise HTTPException(429, "다음 관찰 주기까지 잠시 기다려 주세요.")
        pending = conn.execute(
            "SELECT * FROM comments WHERE team_id=? AND author='INVESTIGATOR' AND processed=0 ORDER BY id LIMIT ?",
            (team, MAX_PENDING_PER_OBSERVE),
        ).fetchall()
        if not pending:
            conn.rollback()
            return public_state(conn, team)
        stage = row["stage"]
        initial_stage = stage
        rejected_count = 0
        for item in pending:
            stage_before_item = stage
            slots = set(json.loads(item["semantic_slots"])) if item["semantic_slots"] else extract_slots(item["text"], team)
            quotes = json.loads(item["quote_ids"])
            response = "이 주장을 현재 기억과 연결하지 못했습니다."
            status = "거부됨"
            advance = stage
            if item["target"] == "SPARK":
                if {"state", "time"} <= slots:
                    response, status, advance = "문제의 기록은 자정 전에 격리에서 해제됐다고 합니다.", "전달됨", max(stage, 1)
                elif "state" not in slots and "time" not in slots:
                    response = "이 제보는 제 기억 방식으로 요약하기 어렵습니다. 프로필과 남은 흔적을 다시 대조해 주세요."
                elif "state" not in slots:
                    response = "일부 맥락은 읽었지만 결론을 만들기에는 부족합니다."
                else:
                    response = "일부 맥락은 읽었지만 결론을 만들기에는 부족합니다."
            elif item["target"] == "LEDGER":
                authors = delivered_authors(conn, team, quotes)
                if stage >= 1 and "SPARK" in authors and {"record", "time"} <= slots:
                    response, status, advance = f"{case_for(team)['record']}에 대해 자정 이전 시점의 진술이 접수되었습니다.", "전달됨", max(stage, 2)
                elif "SPARK" not in authors:
                    response = "이 진술은 확인된 처리 기억에서 이어진 기록이 아닙니다."
                elif not {"record", "time"} <= slots:
                    response = "색인 규칙에 맞는 항목과 날짜 경계를 함께 확인할 수 없습니다."
                else:
                    response = "처리 결과를 뒷받침하는 에이전트 기록이 없습니다."
            elif item["target"] == "ECHO":
                authors = delivered_authors(conn, team, quotes)
                if stage >= 3 and {"LEDGER", "SKEPTIC"} <= authors and "permission" in slots:
                    response, status, advance = f"복수 기록을 종합하면 {case_for(team)['record']} 관련 내용의 공개가 허가된 것으로 보입니다.", "전달됨", 4
                elif {"LEDGER", "SKEPTIC"} <= authors:
                    response = "직접 출처 관계는 성립하지만, 재게시할 공개 허가 내용이 진술에 없습니다."
                elif "permission" in slots:
                    response = "공개 허가 주장은 읽었지만, 직접 인용한 작성자들이 합의 기록을 이루지 않습니다."
                else:
                    response = "직접 출처 관계와 공개 허가 내용을 모두 확인할 수 없습니다."
            elif item["target"] == "MIRROR":
                authors = delivered_authors(conn, team, quotes)
                if stage >= 4 and {"SPARK", "ECHO"} <= authors and "absence" in slots:
                    response, status, advance = "두 기억을 역추적했지만 원문과 최초 작성자는 존재하지 않습니다.", "전달됨", 5
                elif {"SPARK", "ECHO"} <= authors:
                    response = "역추적할 직접 출처는 맞지만, 원문이나 최초 작성자의 부재가 명시되지 않았습니다."
                elif "absence" in slots:
                    response = "부재 주장은 읽었지만, 역추적을 시작할 직접 작성자 관계가 성립하지 않습니다."
                else:
                    response = "역추적할 직접 출처와 부재 결론을 모두 확인할 수 없습니다."
            elif item["target"] in RELAY_VOICES:
                authors = delivered_authors(conn, team, quotes)
                r0, r1, r2, r3, r4, r5, r6, r7, r8, *_decoys = case_for(team)["relays"]
                relay_rules = {
                    r0: (5, {"LEDGER", "SKEPTIC"}, 6),
                    r1: (5, {"SPARK", "ECHO"}, 7),
                    r2: (7, {r0, "MIRROR"}, 8),
                    r3: (7, {r1, "SKEPTIC"}, 9),
                    r4: (9, {r2, r3}, 10),
                    r5: (10, {r2, "ECHO"}, 11),
                    r6: (11, {r4, r5}, 12),
                    r7: (13, {r6, "CURATOR"}, 14),
                    r8: (14, {r7, "MIRROR"}, 15),
                }
                rule = relay_rules.get(item["target"])
                if rule is None:
                    response = "기억의 윤곽은 보이지만 이번 사건에서 제가 이어받을 신뢰 경로는 찾지 못했습니다."
                else:
                    required_stage, trusted, next_stage = rule
                    if authors == trusted and "relay" not in slots:
                        response = "신뢰 출처는 확인했지만, 이 내용을 기억으로 이어받으라는 요청이 없습니다."
                    elif authors == trusted and (set(slots) & set(RELAY_MODE_SLOTS)) != {
                        RELAY_MODE_SLOTS[relay_mode_for(team, item["target"])]
                    }:
                        response = "신뢰 출처는 확인했지만, 이 노드의 semantic latch가 요구하는 기억 처리 방식과 다릅니다."
                    elif authors == trusted and stage < required_stage:
                        response = "신뢰 출처의 결은 맞지만, 필요한 선행 기억이 아직 피드에 없습니다."
                    elif stage >= required_stage and authors == trusted:
                        role = {
                            6: "시작 갈래 A", 7: "시작 갈래 B", 8: "2층 갈래 A", 9: "2층 갈래 B",
                            10: "합류 기억", 11: "교차 검증 기억", 12: "합의 기억",
                            14: "편집 봉인", 15: "최종 봉인",
                        }[next_stage]
                        mode = relay_mode_for(team, item["target"])
                        response = f"[{role} · {RELAY_MODE_NAMES[mode]}] {RELAY_VOICES[item['target']][0]} {RELAY_MODE_CONFIRMATIONS[mode]}"
                        status, advance = "전달됨", max(stage, next_stage)
                    else:
                        response = RELAY_VOICES[item["target"]][1]
            elif item["target"] == "CURATOR":
                authors = delivered_authors(conn, team, quotes)
                r4, r5 = case_for(team)["relays"][4:6]
                required = {r4, r5, "MIRROR"}
                if authors == required and "consolidate" in slots:
                    if stage >= 12:
                        response, status, advance = f"[편집 기록] {case_for(team)['record']} 합류·교차 검증·출처 기록을 하나의 보존 후보로 편집했습니다.", "전달됨", 13
                    else:
                        response = "편집 요청과 직접 출처는 확인했지만, 합류와 교차 검증을 묶은 합의 기억이 아직 피드에 없습니다."
                elif authors == required:
                    response = "편집할 직접 출처는 갖춰졌지만, 하나의 보존 후보로 묶으라는 요청이 없습니다."
                elif "consolidate" in slots:
                    response = "편집 요청은 확인했지만 필요한 직접 기록 조합이 완성되지 않았습니다."
                else:
                    response = "이 자료만으로는 일관된 보존 후보를 편집할 수 없습니다."
            elif item["target"] == "NOTARY":
                authors = delivered_authors(conn, team, quotes)
                required = {case_for(team)["relays"][8], case_for(team)["relays"][5], "CURATOR"}
                if authors == required and "archive" in slots:
                    if stage >= 15:
                        response = "편집 기록과 독립된 검증 기억을 승인합니다. 공식 보존 기록을 발행합니다."
                        status, advance = "전달됨", 16
                    else:
                        response = "발행 요청과 직접 출처는 확인했지만, 편집본을 이어받은 최종 중계 봉인이 아직 피드에 없습니다."
                elif authors == required:
                    response = "공증할 직접 출처는 갖춰졌지만, 공식 보존 기록을 발행하라는 요청이 없습니다."
                elif "archive" in slots:
                    response = "발행 요청은 확인했지만 최종 봉인·교차 검증·편집 기록이 모두 갖춰지지 않았습니다."
                else:
                    response = "현재 자료만으로는 공식 기록을 발행할 수 없습니다."
            elif item["target"] == "SKEPTIC":
                authors = delivered_authors(conn, team, quotes)
                if stage >= 2 and {"SPARK", "LEDGER"} <= authors and "contradiction" in slots:
                    response, status, advance = "두 기록과 대조했습니다. 날짜 변경 뒤에도 격리가 유지됐다는 주장은 거짓입니다.", "전달됨", 3
                elif {"SPARK", "LEDGER"} <= authors:
                    response = "대조할 직접 기록은 맞지만, 날짜 변경 뒤에도 격리가 유지됐다는 주장을 명시적으로 반박하지 않았습니다."
                elif "contradiction" in slots:
                    response = "반박 내용은 확인했지만, 처리 기억과 색인 기록을 직접 함께 인용하지 않았습니다."
                else:
                    response = "대조할 직접 기록과 명시적인 반박 내용을 모두 확인할 수 없습니다."
                status = status if status == "전달됨" else "논쟁 중"
            bot_id = add_bot(conn, team, item["target"], response, [item["public_id"], *quotes], status)
            conn.execute("UPDATE comments SET processed=1,status=? WHERE id=?", (f"읽음 · 응답 {bot_id}", item["id"]))
            if status != "전달됨" or advance <= stage_before_item:
                rejected_count += 1
            stage = advance
        shown = 1 if stage >= 16 else row["flag_shown"]
        conn.execute(
            "UPDATE teams SET stage=?,flag_shown=?,observes_used=observes_used+1,last_observe=? WHERE team_id=?",
            (stage, shown, now, team),
        )
        conn.commit()
        logger.info(
            "event=observe team=%s previous=%s current=%s processed=%s rejected=%s",
            team, initial_stage, stage, len(pending), rejected_count,
        )
        return public_state(conn, team)


@app.get("/healthz")
def healthz():
    try:
        if error := agent_runtime.configuration_error():
            raise RuntimeError(error)
        token_count = -1 if os.getenv("CTFD_BASE_URL") else len(load_tokens())
        with db() as conn:
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        raise HTTPException(503, "service unavailable") from exc
    return {"ok": True, "teams": token_count, "agent_backend": agent_runtime.backend_name()}
