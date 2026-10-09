from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[1]
HANDOUT_DIR = ROOT / ".build" / "for_user"
PUBLIC_HANDOUT_DIR = ROOT.parent / "for_user"
PRIVATE_DIR = ROOT / "private"
NATIVE_DIR = ROOT / "native"

SEED = 0x5EED2026
SERVER_IPS = ("10.13.37.10", "10.13.38.10")
SERVER_PORT = 443
FIXED_OVERHEAD = 29
SEPARATOR_BYTES = 1
WINDOW_BASE = 53248
FINGERPRINT_MODULUS = 251
MAGIC = b"TLF2"
AAD = b"stream-token-length-v2"
KEY_DOMAIN = b"token-length-v2\x00"
DEFAULT_FLAG = "SHA{token_lengths_require_cross_capture_alignment}"
WORDS_PER_LENGTH = 128
SECRET_LENGTHS = (5, 7, 6, 8, 9)
PHRASE_PREFIX = ["the", "recovery", "phrase", "is"]
PHRASE_SUFFIX = [".", "verify", "now"]


def publish_handout() -> None:
    """Copy a complete admin-side build into the public handout directory."""
    if not HANDOUT_DIR.is_dir():
        raise RuntimeError("admin handout build is missing")
    if PUBLIC_HANDOUT_DIR.exists():
        if PUBLIC_HANDOUT_DIR.is_symlink() or not PUBLIC_HANDOUT_DIR.is_dir():
            raise RuntimeError(
                f"refusing to replace non-directory release path: {PUBLIC_HANDOUT_DIR}"
            )
        shutil.rmtree(PUBLIC_HANDOUT_DIR)
    shutil.copytree(HANDOUT_DIR, PUBLIC_HANDOUT_DIR)

def _opaque_word(length: int, counter: int) -> str:
    """Return one fixed-length candidate with no human-word/filler distinction."""
    material = hashlib.shake_256(
        b"token-length-dictionary-v3\x00"
        + bytes([length])
        + counter.to_bytes(4, "big")
    ).digest(length)
    return "".join(chr(ord("a") + value % 26) for value in material)


def _build_word_group(length: int) -> list[str]:
    words: list[str] = []
    seen: set[str] = set()
    counter = 0
    while len(words) < WORDS_PER_LENGTH:
        candidate = _opaque_word(length, counter)
        counter += 1
        if candidate in seen:
            continue
        seen.add(candidate)
        words.append(candidate)
    return words


# Every candidate, including the five selected secrets, comes from the same
# generator and distribution.  The handout therefore has no "real English vs
# q-prefixed filler" classifier.
WORD_GROUPS = {length: _build_word_group(length) for length in SECRET_LENGTHS}

EXTRA_WORDS = [
    "air", "bit", "log", "data", "host", "json", "port", "user",
    "connection", "encryption", "monitoring", "repository", "validation",
    "incident", "operator", "evidence", "archive", "service", "message",
]

KNOWN_TEXTS = {
    "known_alpha": "backup status is ready .",
    "known_beta": "archive synchronization completed without errors .",
}

GENERAL_DECOYS = [
    "the encrypted archive is ready for remote audit . verify now",
    "all customer backups remain stored in separate secure regions . verify now",
    "the recovery service is unavailable during scheduled maintenance . verify now",
    "incident review found no administrator phrase in this session . verify now",
    "the monitoring agent sent a routine validation message today . verify now",
    "archive operator says the repository checksum is still valid . verify now",
    "the evidence service copied an ordinary user record safely . verify now",
    "connection metadata belongs to a retired testing account only . verify now",
    "system backup finished after the nightly encryption rotation . verify now",
    "the support channel contains no privileged recovery material . verify now",
]


def tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+|[.,:!?]", text)


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


def layout_family(tag: int) -> int:
    return avalanche32(tag ^ 0x4C41594F) & 3


def boundary_owner(tag: int, boundary: int) -> int:
    family = layout_family(tag)
    if family == 0:
        value = xorshift32(
            tag ^ ((boundary * 0x9E3779B9) & 0xFFFFFFFF) ^ 0x6D2B79F5
        )
    elif family == 1:
        value = avalanche32(
            ((tag + boundary * 0x85EBCA6B) & 0xFFFFFFFF) ^ 0xB5297A4D
        ) >> 11
    elif family == 2:
        value = xorshift32(
            rotl32(tag, boundary)
            ^ ((boundary * 0xC2B2AE35) & 0xFFFFFFFF)
            ^ 0x27D4EB2F
        ) >> 23
    else:
        rotated = rotl32((boundary * 0x165667B1) & 0xFFFFFFFF, tag >> 27)
        value = avalanche32(((tag ^ rotated) + 0xD3A2646C) & 0xFFFFFFFF) >> 31
    return value & 1


def record_padding(capture_id: int, tag: int, record_index: int) -> int:
    family = layout_family(tag)
    constants = (0xA511E9B3, 0xC0DEC0DE)
    if family == 0:
        value = xorshift32(
            tag ^ constants[capture_id]
            ^ ((record_index * 0x85EBCA6B) & 0xFFFFFFFF)
        )
    elif family == 1:
        value = avalanche32(
            ((tag + capture_id * 0x9E3779B9) & 0xFFFFFFFF)
            ^ ((record_index * 0x27D4EB2F) & 0xFFFFFFFF)
            ^ 0x68E31DA4
        )
    elif family == 2:
        value = xorshift32(
            (rotl32(tag ^ constants[capture_id], record_index * 7 + 3)
             + record_index * 0x165667B1) & 0xFFFFFFFF
        ) >> 4
    else:
        capture_constant = 0x94D049BB if capture_id else 0x369DEA0F
        value = avalanche32(
            tag ^ (((record_index + 1) * 0x7F4A7C15) & 0xFFFFFFFF)
            ^ capture_constant
        ) >> 19
    return value & 7


def record_layout(capture_id: int, tag: int, token_count: int) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    start = 0
    count = 0
    record_index = 0
    for index in range(token_count):
        count += 1
        boundary = index + 1
        cut = boundary == token_count or count == 3
        if not cut and boundary_owner(tag, boundary) == capture_id:
            cut = True
        if cut:
            result.append((start, count, record_padding(capture_id, tag, record_index)))
            start += count
            count = 0
            record_index += 1
    return result


def fingerprint_family(capture_id: int, tag: int, record_index: int) -> int:
    return avalanche32(
        tag
        ^ ((capture_id * 0x9E3779B9) & 0xFFFFFFFF)
        ^ ((record_index * 0x85EBCA6B) & 0xFFFFFFFF)
        ^ 0x4650524E
    ) & 3


def fingerprint_update(family: int, state: int, value: int) -> int:
    if family == 0:
        return ((state ^ value) * 0x01000193) & 0xFFFFFFFF
    if family == 1:
        return rotl32((state + value + 0x7F4A7C15) & 0xFFFFFFFF, 5) ^ 0xA5A5A5A5
    if family == 2:
        state ^= value
        for _ in range(8):
            state = (state >> 1) ^ (0xEDB88320 if state & 1 else 0)
        return state & 0xFFFFFFFF
    state = (state + value + 0x9E3779B9) & 0xFFFFFFFF
    state ^= state >> 16
    state = (state * 0x21F0AAAD) & 0xFFFFFFFF
    return rotl32(state, 13)


def batch_fingerprint(capture_id: int, tag: int, record_index: int, tokens: list[str]) -> int:
    family = fingerprint_family(capture_id, tag, record_index)
    constants = (0x243F6A88, 0x85A308D3)
    if family == 0:
        state = (
            0x811C9DC5 ^ constants[capture_id] ^ tag
            ^ ((record_index * 0x9E3779B9) & 0xFFFFFFFF)
        )
    elif family == 1:
        state = avalanche32(
            (tag + constants[capture_id] + record_index * 0xC2B2AE35) & 0xFFFFFFFF
        )
    elif family == 2:
        state = (
            0xFFFFFFFF ^ tag ^ rotl32(constants[capture_id], record_index)
        ) & 0xFFFFFFFF
    else:
        state = (
            (0x9E3779B9 + tag) ^ constants[capture_id]
            ^ ((record_index * 0x27D4EB2F) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF

    # A one-token record intentionally reveals no content fingerprint.
    if len(tokens) > 1:
        for token_index, token in enumerate(tokens):
            if token_index:
                state = fingerprint_update(family, state, 0xFF)
            for value in token.encode("utf-8"):
                state = fingerprint_update(family, state, value)
    if family == 1:
        state = avalanche32(state ^ ((len(tokens) * 0x9E3779B9) & 0xFFFFFFFF))
    elif family == 2:
        state ^= state >> 16
    elif family == 3:
        state = avalanche32(
            (state + len(tokens) * 0x85EBCA6B) & 0xFFFFFFFF
        )
    return state % FINGERPRINT_MODULUS


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    packet_id: int,
    window: int = 64240,
) -> bytes:
    src_raw = socket.inet_aton(src_ip)
    dst_raw = socket.inet_aton(dst_ip)
    tcp_offset_flags = (5 << 12) | flags
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, tcp_offset_flags, window, 0, 0
    )
    pseudo = src_raw + dst_raw + struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
    tcp_sum = checksum(pseudo + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, tcp_offset_flags, window, tcp_sum, 0
    )
    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, packet_id & 0xFFFF,
        0x4000, 64, 6, 0, src_raw, dst_raw
    )
    ip_sum = checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_length, packet_id & 0xFFFF,
        0x4000, 64, 6, ip_sum, src_raw, dst_raw
    )
    return bytes.fromhex("0200000000010200000000020800") + ip_header + tcp_header + payload


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in sorted(packets, key=lambda item: item[0]):
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            output.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            output.write(frame)


def split_stream(stream: bytes, rng: random.Random) -> list[bytes]:
    chunks: list[bytes] = []
    offset = 0
    while offset < len(stream):
        size = rng.randrange(23, 92)
        chunks.append(stream[offset:offset + size])
        offset += size
    return chunks


def build_session_packets(
    capture_id: int,
    logical_index: int,
    name: str,
    tag: int,
    tokens: list[str],
    rng: random.Random,
    start_time: float,
) -> tuple[list[tuple[float, bytes]], dict[str, object]]:
    server_ip = SERVER_IPS[capture_id]
    client_ip = f"10.{40 + capture_id}.{1 + logical_index // 200}.{20 + logical_index % 200}"
    client_port = 41000 + ((logical_index * 977 + capture_id * 313) % 20000)
    client_isn = rng.randrange(100_000, 900_000)
    server_isn = rng.randrange(1_000_000, 9_000_000)
    packet_id = 1000 + logical_index * 100
    packets: list[tuple[float, bytes]] = []

    def add(
        delta: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b"",
        window: int = 64240,
    ) -> None:
        nonlocal packet_id
        packets.append(
            (
                start_time + delta,
                build_frame(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, packet_id, window),
            )
        )
        packet_id += 1

    add(0.000, client_ip, server_ip, client_port, SERVER_PORT, client_isn, 0, 0x02)
    add(0.001, server_ip, client_ip, SERVER_PORT, client_port, server_isn, client_isn + 1, 0x12)
    add(0.002, client_ip, server_ip, client_port, SERVER_PORT, client_isn + 1, server_isn + 1, 0x10)

    request = b"TLQ2" + struct.pack("!IB", tag, len(tokens)) + rng.randbytes(23)
    add(0.006, client_ip, server_ip, client_port, SERVER_PORT, client_isn + 1, server_isn + 1, 0x18, request)
    client_next = client_isn + 1 + len(request)

    token_lengths = [len(token.encode("utf-8")) for token in tokens]
    layouts = record_layout(capture_id, tag, len(tokens))
    fragment_lengths: list[int] = []
    records: list[bytes] = []
    fingerprints: list[int] = []
    for record_index, (start, count, pad) in enumerate(layouts):
        clear_length = sum(token_lengths[start:start + count]) + SEPARATOR_BYTES * (count - 1)
        fragment_length = FIXED_OVERHEAD + clear_length + pad
        fragment_lengths.append(fragment_length)
        records.append(struct.pack("!BHH", 0x17, 0x0303, fragment_length) + rng.randbytes(fragment_length))
        fingerprints.append(batch_fingerprint(capture_id, tag, record_index, tokens[start:start + count]))
    stream = b"".join(records)
    chunks = split_stream(stream, rng)

    server_seq = server_isn + 1
    segment_info: list[tuple[int, bytes, float]] = []
    for index, chunk in enumerate(chunks):
        # Adjacent chunks occasionally arrive out of timestamp order; TCP sequence is authoritative.
        jitter = -0.005 if index % 5 == 4 else 0.0
        delta = 0.020 + index * 0.011 + jitter
        segment_info.append((server_seq, chunk, delta))
        add(delta, server_ip, client_ip, SERVER_PORT, client_port, server_seq, client_next, 0x18, chunk)
        server_seq += len(chunk)
    if logical_index % 3 == 0 and len(segment_info) >= 2:
        seq, chunk, delta = segment_info[1]
        add(delta + 0.004, server_ip, client_ip, SERVER_PORT, client_port, seq, client_next, 0x18, chunk)

    cumulative = 0
    for record_index, (record, fingerprint) in enumerate(zip(records, fingerprints)):
        cumulative += len(record)
        add(
            0.024 + record_index * 0.0087,
            client_ip,
            server_ip,
            client_port,
            SERVER_PORT,
            client_next,
            server_isn + 1 + cumulative,
            0x10,
            window=WINDOW_BASE + fingerprint,
        )

    finish = 0.035 + len(chunks) * 0.012
    add(finish, server_ip, client_ip, SERVER_PORT, client_port, server_seq, client_next, 0x11)
    add(finish + 0.001, client_ip, server_ip, client_port, SERVER_PORT, client_next, server_seq + 1, 0x10)
    return packets, {
        "name": name,
        "tag": f"0x{tag:08x}",
        "layout_family": layout_family(tag),
        "capture": capture_id,
        "client_ip": client_ip,
        "client_port": client_port,
        "tokens": tokens,
        "token_lengths": token_lengths,
        "layout": [
            {
                "start": start,
                "count": count,
                "pad": pad,
                "fingerprint_family": fingerprint_family(capture_id, tag, record_index),
            }
            for record_index, (start, count, pad) in enumerate(layouts)
        ],
        "fragment_lengths": fragment_lengths,
        "fingerprints": fingerprints,
    }


def validate_word_groups() -> None:
    expected_counts = {length: WORDS_PER_LENGTH for length in WORD_GROUPS}
    all_words: list[str] = []
    for length, words in WORD_GROUPS.items():
        if len(words) != expected_counts[length]:
            raise ValueError(f"wrong candidate count for length {length}")
        if any(len(word.encode("ascii")) != length for word in words):
            raise ValueError(f"wrong word length in group {length}")
        all_words.extend(words)
    if len(all_words) != len(set(all_words)):
        raise ValueError("duplicate dictionary word")
    if tuple(WORD_GROUPS) != SECRET_LENGTHS:
        raise ValueError("candidate length groups drifted")


def choose_secret_words(rng: random.Random) -> list[str]:
    """Choose secrets independently of dictionary order and packet randomness."""
    return [rng.choice(WORD_GROUPS[length]) for length in SECRET_LENGTHS]


def phrase_decoys(rng: random.Random) -> list[list[str]]:
    secret_lengths = SECRET_LENGTHS
    lengths = sorted(WORD_GROUPS)
    vectors: set[tuple[int, ...]] = set()
    while len(vectors) < 11:
        candidate = tuple(rng.choice(lengths) for _ in range(5))
        if candidate != secret_lengths:
            vectors.add(candidate)
    result = []
    for vector in sorted(vectors):
        words = [rng.choice(WORD_GROUPS[length]) for length in vector]
        result.append([*PHRASE_PREFIX, *words, *PHRASE_SUFFIX])
    return result


def _layout_connected(tag: int, token_count: int, capture_ids: tuple[int, ...]) -> bool:
    graph: dict[int, set[int]] = {index: set() for index in range(token_count + 1)}
    for capture_id in capture_ids:
        for start, count, _pad in record_layout(capture_id, tag, token_count):
            end = start + count
            graph[start].add(end)
            graph[end].add(start)
    reached = {0}
    pending = [0]
    while pending:
        current = pending.pop()
        for neighbor in graph[current] - reached:
            reached.add(neighbor)
            pending.append(neighbor)
    return len(reached) == token_count + 1


def _admin_fingerprint_families(tag: int, token_count: int) -> set[int]:
    families: set[int] = set()
    for capture_id in (0, 1):
        for record_index, (start, count, _pad) in enumerate(
            record_layout(capture_id, tag, token_count)
        ):
            if count > 1 and set(range(start, start + count)) & set(range(4, 9)):
                families.add(fingerprint_family(capture_id, tag, record_index))
    return families


def _secret_constraint_graph_connected(tag: int, token_count: int) -> bool:
    """Reject tags whose multi-token evidence splits the five secret words."""
    secret_positions = set(range(4, 9))
    graph = {position: set() for position in secret_positions}
    covered: set[int] = set()
    for capture_id in (0, 1):
        for start, count, _pad in record_layout(capture_id, tag, token_count):
            if count == 1:
                continue
            variables = secret_positions & set(range(start, start + count))
            covered.update(variables)
            for source in variables:
                graph[source].update(variables - {source})
    if covered != secret_positions:
        return False
    reached = {4}
    pending = [4]
    while pending:
        current = pending.pop()
        for neighbor in graph[current] - reached:
            reached.add(neighbor)
            pending.append(neighbor)
    return reached == secret_positions


def choose_session_tags(
    rng: random.Random,
    sessions: list[tuple[str, list[str], str]],
) -> list[int]:
    """Choose tags that preserve the intended cross-capture/family invariants."""
    tags: list[int] = []
    used: set[int] = set()
    for _index, (name, tokens, category) in enumerate(sessions):
        for _attempt in range(100_000):
            tag = rng.randrange(0x20000000, 0xE0000000)
            if tag in used or not _layout_connected(tag, len(tokens), (0, 1)):
                continue
            if category in {"admin", "phrase-decoy"} and not _secret_constraint_graph_connected(
                tag, len(tokens)
            ):
                continue
            if name == "admin":
                if _layout_connected(tag, len(tokens), (0,)):
                    continue
                if _layout_connected(tag, len(tokens), (1,)):
                    continue
                if _admin_fingerprint_families(tag, len(tokens)) != {0, 1, 2, 3}:
                    continue
            tags.append(tag)
            used.add(tag)
            break
        else:
            raise RuntimeError(f"could not choose a valid flow tag for {name}")

    missing = {0, 1, 2, 3} - {layout_family(tag) for tag in tags}
    replaceable = [
        index for index, (name, _tokens, _category) in enumerate(sessions)
        if name.startswith("general_decoy_")
    ]
    for wanted, index in zip(sorted(missing), reversed(replaceable)):
        _name, tokens, _category = sessions[index]
        used.remove(tags[index])
        for _attempt in range(100_000):
            tag = rng.randrange(0x20000000, 0xE0000000)
            if (
                tag not in used
                and layout_family(tag) == wanted
                and _layout_connected(tag, len(tokens), (0, 1))
            ):
                tags[index] = tag
                used.add(tag)
                break
        else:
            raise RuntimeError(f"could not cover layout family {wanted}")
    return tags


def load_flag() -> str:
    flag_file = os.environ.get("TLF_FLAG_FILE")
    if flag_file:
        raw = Path(flag_file).read_bytes().rstrip(b"\r\n")
        try:
            flag = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("flag must be valid UTF-8") from error
    else:
        flag = DEFAULT_FLAG
    if not (flag.startswith("SHA{") and flag.endswith("}") and 8 <= len(flag.encode()) <= 192):
        raise ValueError("flag must be 8..192 UTF-8 bytes and use SHA{...} format")
    return flag


def encrypt_flag(phrase: str, flag: str, rng: random.Random) -> bytes:
    key = hashlib.sha256(KEY_DOMAIN + phrase.encode("utf-8")).digest()
    nonce = rng.randbytes(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, flag.encode("utf-8"), AAD)


def generate_challenge() -> None:
    print("[1/5] 사전·이중 캡처 규칙 검증")
    validate_word_groups()
    flag = load_flag()
    if HANDOUT_DIR.exists():
        for child in HANDOUT_DIR.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        HANDOUT_DIR.mkdir(parents=True)
    if PRIVATE_DIR.exists():
        shutil.rmtree(PRIVATE_DIR)
    PRIVATE_DIR.mkdir(parents=True)
    dictionary_rng = random.Random(SEED ^ 0xD1C710A3)
    secret_rng = random.Random(SEED ^ 0x5EC2E7A1)
    session_rng = random.Random(SEED ^ 0x5E55104E)
    encryption_rng = random.Random(SEED ^ 0xEAC2A55E)

    dictionary = [word for words in WORD_GROUPS.values() for word in words] + EXTRA_WORDS
    dictionary_rng.shuffle(dictionary)
    secret_words = choose_secret_words(secret_rng)
    phrase = " ".join(secret_words)

    print("[2/5] 24개 논리 세션 구성")
    sessions: list[tuple[str, list[str], str]] = [
        (name, tokenize(text), "known") for name, text in KNOWN_TEXTS.items()
    ]
    sessions.append(("admin", [*PHRASE_PREFIX, *secret_words, *PHRASE_SUFFIX], "admin"))
    sessions.extend(
        (f"phrase_decoy_{index:02d}", tokens, "phrase-decoy")
        for index, tokens in enumerate(phrase_decoys(session_rng))
    )
    sessions.extend(
        (f"general_decoy_{index:02d}", tokenize(text), "general-decoy")
        for index, text in enumerate(GENERAL_DECOYS)
    )
    if len(sessions) != 24:
        raise RuntimeError("session count drifted")
    tags = choose_session_tags(session_rng, sessions)

    print("[3/5] 분석 파일과 봉인 플래그 생성")
    subprocess.run(
        [
            "gcc", "-std=c11", "-O2", "-static", "-s", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            str(NATIVE_DIR / "record_layout.c"), "-o", str(HANDOUT_DIR / "record_layout"),
        ],
        check=True,
    )
    subprocess.run(
        [
            "gcc", "-std=c11", "-O2", "-static", "-s", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
            str(NATIVE_DIR / "batch_model.c"), "-o", str(HANDOUT_DIR / "batch_model"),
        ],
        check=True,
    )
    (HANDOUT_DIR / "dictionary.txt").write_text("\n".join(dictionary) + "\n", encoding="utf-8")
    known_lines = []
    for (name, tokens, category), tag in zip(sessions, tags):
        if category == "known":
            known_lines.append(f"0x{tag:08x}|" + " | ".join(tokens))
    (HANDOUT_DIR / "known_sessions.txt").write_text("\n".join(known_lines) + "\n", encoding="utf-8")
    (HANDOUT_DIR / "flag.enc").write_bytes(encrypt_flag(phrase, flag, encryption_rng))
    (HANDOUT_DIR / "capture_manifest.json").write_text(
        json.dumps(
            {
                "captures": [
                    {"id": 0, "file": "capture_a.pcap", "server": SERVER_IPS[0]},
                    {"id": 1, "file": "capture_b.pcap", "server": SERVER_IPS[1]},
                ],
                "request_marker": "TLQ2 || tag(u32 big-endian) || token_count(u8)",
                "record_header": "type(u8=0x17) || version(u16=0x0303) || fragment_length(u16 big-endian)",
                "batch_size": "1..3 tokens",
                "batch_separator_bytes": SEPARATOR_BYTES,
                "target_message_shape": (
                    "the recovery phrase is <dictionary word 1> <dictionary word 2> "
                    "<dictionary word 3> <dictionary word 4> <dictionary word 5> . verify now"
                ),
                "native_models": {
                    "files": ["record_layout", "batch_model"],
                    "interface": "fixed embedded self-test only; arbitrary-query CLI is not provided",
                    "layout_families": 4,
                    "fingerprint_families": 4,
                },
                "ack_window_side_channel": {
                    "range": [WINDOW_BASE, WINDOW_BASE + FINGERPRINT_MODULUS - 1],
                    "meaning": (
                        "one batch fingerprint per record; a one-token record is deliberately "
                        "content-independent"
                    ),
                },
                "flag_envelope": "TLF2 || nonce(12) || AES-256-GCM ciphertext+tag",
                "flag_seal": {
                    "aead": "AES-256-GCM",
                    "aad_ascii": AAD.decode("ascii"),
                    "key": "SHA-256(key_domain || recovery_phrase UTF-8)",
                    "key_domain_ascii": KEY_DOMAIN[:-1].decode("ascii"),
                    "key_domain_has_trailing_nul": True,
                    "recovery_phrase_joiner_ascii": " ",
                },
                "flag_format": "SHA{...}",
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print("[4/5] TCP 분할·병합·재전송이 섞인 PCAP 두 개 생성")
    all_metadata: list[dict[str, object]] = []
    for capture_id, filename in enumerate(("capture_a.pcap", "capture_b.pcap")):
        capture_rng = random.Random(SEED ^ (0xCA970001 + capture_id * 0x10101))
        packets: list[tuple[float, bytes]] = []
        base_time = 1_782_000_000.0 + capture_id * 300
        wire_order = list(range(len(sessions)))
        capture_rng.shuffle(wire_order)
        for wire_index, logical_index in enumerate(wire_order):
            name, tokens, category = sessions[logical_index]
            tag = tags[logical_index]
            session_packets, metadata = build_session_packets(
                capture_id,
                wire_index,
                name,
                tag,
                tokens,
                capture_rng,
                base_time + (wire_index % 8) * 0.003 + (wire_index // 8) * 0.0004,
            )
            metadata["category"] = category
            metadata["wire_index"] = wire_index
            packets.extend(session_packets)
            all_metadata.append(metadata)
        write_pcap(HANDOUT_DIR / filename, packets)

    print("[5/5] 운영자 메타데이터 기록")
    (PRIVATE_DIR / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    (PRIVATE_DIR / "recovery_phrase.txt").write_text(phrase + "\n", encoding="utf-8")
    (PRIVATE_DIR / "sessions.json").write_text(
        json.dumps(
            {
                "fixed_overhead": FIXED_OVERHEAD,
                "separator_bytes": SEPARATOR_BYTES,
                "session_count": len(sessions),
                "sessions": all_metadata,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print("완료: for_admin/.build/for_user에 지급본 생성")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Token Length Forensics inside for_admin")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="after generating, replace ../for_user with a copy of the admin build",
    )
    arguments = parser.parse_args()
    generate_challenge()
    if arguments.publish:
        publish_handout()
