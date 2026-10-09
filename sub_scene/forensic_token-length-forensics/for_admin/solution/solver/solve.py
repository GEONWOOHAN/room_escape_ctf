from __future__ import annotations

import hashlib
import os
import socket
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Iterable, Iterator, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parents[2]
HANDOUT_DIR = Path(os.environ.get("TLF_HANDOUT_DIR", ROOT.parent / "for_user")).resolve()
CAPTURE_PATHS = (HANDOUT_DIR / "capture_a.pcap", HANDOUT_DIR / "capture_b.pcap")
KNOWN_PATH = HANDOUT_DIR / "known_sessions.txt"
DICTIONARY_PATH = HANDOUT_DIR / "dictionary.txt"
ENCRYPTED_FLAG_PATH = HANDOUT_DIR / "flag.enc"

SERVER_IPS = ("10.13.37.10", "10.13.38.10")
SERVER_PORT = 443
SEPARATOR_BYTES = 1
WINDOW_BASE = 53248
FINGERPRINT_MODULUS = 251
PHRASE_PREFIX_LENGTHS = [3, 8, 6, 2]
PHRASE_SUFFIX_LENGTHS = [1, 6, 3]
MAGIC = b"TLF2"
AAD = b"stream-token-length-v2"
KEY_DOMAIN = b"token-length-v2\x00"
T = TypeVar("T")


@dataclass(frozen=True)
class TcpPayload:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes


@dataclass(frozen=True)
class FlowObservation:
    tag: int
    token_count: int
    fragment_lengths: tuple[int, ...]
    fingerprints: tuple[int, ...]


def _read_pcap_frames(path: Path) -> Iterator[tuple[float, bytes]]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("missing PCAP header")
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("unsupported PCAP")
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated packet header")
        seconds, micros, captured, _ = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        frame = data[offset:offset + captured]
        if len(frame) != captured:
            raise ValueError("truncated packet")
        offset += captured
        yield seconds + micros / 1_000_000, frame


def _parse_tcp_payload(timestamp: float, frame: bytes) -> TcpPayload | None:
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip_start = 14
    ihl = (frame[ip_start] & 0x0F) * 4
    if frame[ip_start] >> 4 != 4 or ihl < 20 or frame[ip_start + 9] != 6:
        return None
    total_length = struct.unpack_from("!H", frame, ip_start + 2)[0]
    src_ip = socket.inet_ntoa(frame[ip_start + 12:ip_start + 16])
    dst_ip = socket.inet_ntoa(frame[ip_start + 16:ip_start + 20])
    tcp_start = ip_start + ihl
    if tcp_start + 20 > len(frame):
        return None
    src_port, dst_port, seq, ack = struct.unpack_from("!HHII", frame, tcp_start)
    offset_flags, window = struct.unpack_from("!HH", frame, tcp_start + 12)
    flags = offset_flags & 0x01FF
    tcp_length = (frame[tcp_start + 12] >> 4) * 4
    payload_start = tcp_start + tcp_length
    payload_end = ip_start + total_length
    if payload_start > payload_end or payload_end > len(frame):
        return None
    payload = frame[payload_start:payload_end]
    return TcpPayload(timestamp, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload)


def reassemble_tcp(packets: Iterable[TcpPayload]) -> bytes:
    byte_map: dict[int, int] = {}
    for packet in sorted(packets, key=lambda item: (item.seq, item.timestamp)):
        for offset, value in enumerate(packet.payload):
            position = packet.seq + offset
            previous = byte_map.setdefault(position, value)
            if previous != value:
                raise ValueError("conflicting retransmission")
    if not byte_map:
        return b""
    first, last = min(byte_map), max(byte_map)
    if len(byte_map) != last - first + 1:
        raise ValueError("missing TCP bytes")
    return bytes(byte_map[position] for position in range(first, last + 1))


def parse_record_lengths(stream: bytes) -> list[int]:
    result: list[int] = []
    offset = 0
    while offset < len(stream):
        if offset + 5 > len(stream):
            raise ValueError("truncated record header")
        content_type, version, fragment_length = struct.unpack_from("!BHH", stream, offset)
        if content_type != 0x17 or version != 0x0303:
            raise ValueError("invalid record")
        offset += 5
        if offset + fragment_length > len(stream):
            raise ValueError("truncated record body")
        offset += fragment_length
        result.append(fragment_length)
    return result


def extract_capture(path: Path, server_ip: str) -> dict[int, FlowObservation]:
    requests: dict[tuple[str, int], tuple[int, int]] = {}
    responses: dict[tuple[str, int], list[TcpPayload]] = defaultdict(list)
    markers: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
    for timestamp, frame in _read_pcap_frames(path):
        packet = _parse_tcp_payload(timestamp, frame)
        if packet is None:
            continue
        if packet.dst_ip == server_ip and packet.dst_port == SERVER_PORT and packet.payload.startswith(b"TLQ2"):
            if len(packet.payload) < 9:
                raise ValueError("truncated TLQ2 request")
            tag, token_count = struct.unpack_from("!IB", packet.payload, 4)
            requests[(packet.src_ip, packet.src_port)] = (tag, token_count)
        elif packet.src_ip == server_ip and packet.src_port == SERVER_PORT:
            if packet.payload:
                responses[(packet.dst_ip, packet.dst_port)].append(packet)
        elif (
            packet.dst_ip == server_ip
            and packet.dst_port == SERVER_PORT
            and not packet.payload
            and WINDOW_BASE <= packet.window < WINDOW_BASE + FINGERPRINT_MODULUS
        ):
            markers[(packet.src_ip, packet.src_port)].append((packet.ack, packet.window - WINDOW_BASE))
    result: dict[int, FlowObservation] = {}
    for endpoint, (tag, token_count) in requests.items():
        lengths = tuple(parse_record_lengths(reassemble_tcp(responses[endpoint])))
        fingerprints = tuple(value for _ack, value in sorted(set(markers[endpoint])))
        if len(fingerprints) != len(lengths):
            raise ValueError("record fingerprint count mismatch")
        if tag in result:
            raise ValueError("duplicate flow tag")
        result[tag] = FlowObservation(tag, token_count, lengths, fingerprints)
    return result


def load_known_sessions() -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for line in KNOWN_PATH.read_text(encoding="utf-8").splitlines():
        raw_tag, raw_tokens = line.split("|", 1)
        result[int(raw_tag, 0)] = [token.strip() for token in raw_tokens.split("|") if token.strip()]
    return result


def _rotl32(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    amount &= 31
    if amount == 0:
        return value
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def _xorshift32(value: int) -> int:
    value &= 0xFFFFFFFF
    value ^= (value << 13) & 0xFFFFFFFF
    value ^= value >> 17
    value ^= (value << 5) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def _avalanche32(value: int) -> int:
    value &= 0xFFFFFFFF
    value ^= value >> 16
    value = (value * 0x7FEB352D) & 0xFFFFFFFF
    value ^= value >> 15
    value = (value * 0x846CA68B) & 0xFFFFFFFF
    value ^= value >> 16
    return value & 0xFFFFFFFF


def recovered_layout_family(tag: int) -> int:
    return _avalanche32(tag ^ 0x4C41594F) & 3


def _recovered_boundary_owner(tag: int, boundary: int) -> int:
    family = recovered_layout_family(tag)
    if family == 0:
        value = _xorshift32(
            tag ^ ((boundary * 0x9E3779B9) & 0xFFFFFFFF) ^ 0x6D2B79F5
        )
    elif family == 1:
        value = _avalanche32(
            ((tag + boundary * 0x85EBCA6B) & 0xFFFFFFFF) ^ 0xB5297A4D
        ) >> 11
    elif family == 2:
        value = _xorshift32(
            _rotl32(tag, boundary)
            ^ ((boundary * 0xC2B2AE35) & 0xFFFFFFFF)
            ^ 0x27D4EB2F
        ) >> 23
    else:
        rotated = _rotl32((boundary * 0x165667B1) & 0xFFFFFFFF, tag >> 27)
        value = _avalanche32(((tag ^ rotated) + 0xD3A2646C) & 0xFFFFFFFF) >> 31
    return value & 1


def _recovered_padding(capture_id: int, tag: int, record_index: int) -> int:
    family = recovered_layout_family(tag)
    constants = (0xA511E9B3, 0xC0DEC0DE)
    if family == 0:
        value = _xorshift32(
            tag ^ constants[capture_id]
            ^ ((record_index * 0x85EBCA6B) & 0xFFFFFFFF)
        )
    elif family == 1:
        value = _avalanche32(
            ((tag + capture_id * 0x9E3779B9) & 0xFFFFFFFF)
            ^ ((record_index * 0x27D4EB2F) & 0xFFFFFFFF)
            ^ 0x68E31DA4
        )
    elif family == 2:
        value = _xorshift32(
            (_rotl32(tag ^ constants[capture_id], record_index * 7 + 3)
             + record_index * 0x165667B1) & 0xFFFFFFFF
        ) >> 4
    else:
        capture_constant = 0x94D049BB if capture_id else 0x369DEA0F
        value = _avalanche32(
            tag ^ (((record_index + 1) * 0x7F4A7C15) & 0xFFFFFFFF)
            ^ capture_constant
        ) >> 19
    return value & 7


def recovered_layout(
    capture_id: int,
    tag: int,
    token_count: int,
) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    start = count = record_index = 0
    for index in range(token_count):
        count += 1
        boundary = index + 1
        cut = boundary == token_count or count == 3
        if not cut and _recovered_boundary_owner(tag, boundary) == capture_id:
            cut = True
        if cut:
            result.append((start, count, _recovered_padding(capture_id, tag, record_index)))
            start += count
            count = 0
            record_index += 1
    return result


def derive_overhead(captures: tuple[dict[int, FlowObservation], ...]) -> int:
    candidates: set[int] = set()
    for tag, tokens in load_known_sessions().items():
        token_lengths = [len(token.encode("utf-8")) for token in tokens]
        for capture_id, observations in enumerate(captures):
            flow = observations[tag]
            layout = recovered_layout(capture_id, tag, flow.token_count)
            for fragment, (start, count, pad) in zip(flow.fragment_lengths, layout):
                clear = sum(token_lengths[start:start + count]) + SEPARATOR_BYTES * (count - 1)
                candidates.add(fragment - clear - pad)
    if len(candidates) != 1:
        raise ValueError(f"fixed overhead is ambiguous: {sorted(candidates)}")
    return candidates.pop()


def recover_token_lengths(
    tag: int,
    observations: tuple[FlowObservation, ...],
    overhead: int,
    capture_ids: tuple[int, ...] = (0, 1),
) -> list[int]:
    token_count = observations[0].token_count
    if any(flow.token_count != token_count for flow in observations):
        raise ValueError("paired token count mismatch")
    graph: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for capture_id, flow in zip(capture_ids, observations):
        layout = recovered_layout(capture_id, tag, token_count)
        if len(layout) != len(flow.fragment_lengths):
            raise ValueError("layout/record mismatch")
        for fragment, (start, count, pad) in zip(flow.fragment_lengths, layout):
            total = fragment - overhead - SEPARATOR_BYTES * (count - 1) - pad
            end = start + count
            graph[start].append((end, total))
            graph[end].append((start, -total))
    prefix = {0: 0}
    queue = deque([0])
    while queue:
        source = queue.popleft()
        for target, delta in graph[source]:
            value = prefix[source] + delta
            if target in prefix:
                if prefix[target] != value:
                    raise ValueError("inconsistent length equations")
            else:
                prefix[target] = value
                queue.append(target)
    if len(prefix) != token_count + 1:
        raise ValueError("one capture is insufficient; combine both captures")
    lengths = [prefix[index + 1] - prefix[index] for index in range(token_count)]
    if any(length <= 0 or length > 64 for length in lengths):
        raise ValueError("invalid recovered token length")
    return lengths


def candidate_secret_vectors(
    captures: tuple[dict[int, FlowObservation], dict[int, FlowObservation]],
    overhead: int,
) -> list[tuple[int, tuple[int, ...]]]:
    candidates = []
    for tag in sorted(set(captures[0]) & set(captures[1])):
        first, second = captures[0][tag], captures[1][tag]
        if first.token_count != 12:
            continue
        lengths = recover_token_lengths(tag, (first, second), overhead)
        if lengths[:4] == PHRASE_PREFIX_LENGTHS and lengths[9:] == PHRASE_SUFFIX_LENGTHS:
            candidates.append((tag, tuple(lengths[4:9])))
    return candidates


def recovered_fingerprint_family(capture_id: int, tag: int, record_index: int) -> int:
    return _avalanche32(
        tag
        ^ ((capture_id * 0x9E3779B9) & 0xFFFFFFFF)
        ^ ((record_index * 0x85EBCA6B) & 0xFFFFFFFF)
        ^ 0x4650524E
    ) & 3


def _build_crc32_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        state = value
        for _ in range(8):
            state = (state >> 1) ^ (0xEDB88320 if state & 1 else 0)
        table.append(state & 0xFFFFFFFF)
    return tuple(table)


CRC32_TABLE = _build_crc32_table()


def recovered_batch_fingerprint(
    capture_id: int,
    tag: int,
    record_index: int,
    tokens: list[str],
) -> int:
    family = recovered_fingerprint_family(capture_id, tag, record_index)
    constants = (0x243F6A88, 0x85A308D3)
    if family == 0:
        state = (
            0x811C9DC5 ^ constants[capture_id] ^ tag
            ^ ((record_index * 0x9E3779B9) & 0xFFFFFFFF)
        )
    elif family == 1:
        state = _avalanche32(
            (tag + constants[capture_id] + record_index * 0xC2B2AE35) & 0xFFFFFFFF
        )
    elif family == 2:
        state = (
            0xFFFFFFFF ^ tag ^ _rotl32(constants[capture_id], record_index)
        ) & 0xFFFFFFFF
    else:
        state = (
            (0x9E3779B9 + tag) ^ constants[capture_id]
            ^ ((record_index * 0x27D4EB2F) & 0xFFFFFFFF)
        ) & 0xFFFFFFFF
    if len(tokens) > 1:
        payload = b"\xff".join(token.encode("utf-8") for token in tokens)
        if family == 0:
            for value in payload:
                state = ((state ^ value) * 0x01000193) & 0xFFFFFFFF
        elif family == 1:
            for value in payload:
                state = _rotl32(
                    (state + value + 0x7F4A7C15) & 0xFFFFFFFF, 5
                ) ^ 0xA5A5A5A5
        elif family == 2:
            for value in payload:
                state = (state >> 8) ^ CRC32_TABLE[(state ^ value) & 0xFF]
        else:
            for value in payload:
                state = (state + value + 0x9E3779B9) & 0xFFFFFFFF
                state ^= state >> 16
                state = (state * 0x21F0AAAD) & 0xFFFFFFFF
                state = _rotl32(state, 13)
    if family == 1:
        state = _avalanche32(state ^ ((len(tokens) * 0x9E3779B9) & 0xFFFFFFFF))
    elif family == 2:
        state ^= state >> 16
    elif family == 3:
        state = _avalanche32(
            (state + len(tokens) * 0x85EBCA6B) & 0xFFFFFFFF
        )
    return state % FINGERPRINT_MODULUS


def recover_phrase_candidates(
    tag: int,
    vector: tuple[int, ...],
    captures: tuple[dict[int, FlowObservation], dict[int, FlowObservation]],
) -> list[str]:
    dictionary = [
        line.strip() for line in DICTIONARY_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    domains = [
        [word for word in dictionary if len(word.encode("utf-8")) == length]
        for length in vector
    ]
    fixed = {
        0: "the", 1: "recovery", 2: "phrase", 3: "is",
        9: ".", 10: "verify", 11: "now",
    }
    constraints: list[tuple[int, int, tuple[int, ...], tuple[int, ...], int]] = []
    for capture_id, observations in enumerate(captures):
        flow = observations[tag]
        for record_index, ((start, count, _pad), expected) in enumerate(
            zip(recovered_layout(capture_id, tag, 12), flow.fingerprints)
        ):
            positions = tuple(range(start, start + count))
            raw_variables = tuple(position - 4 for position in positions if 4 <= position <= 8)
            # Singleton records deliberately reveal no token-content fingerprint.
            variables = () if len(positions) == 1 else raw_variables
            constraints.append((capture_id, record_index, positions, variables, expected))

    def evaluate_constraint(
        constraint: tuple[int, int, tuple[int, ...], tuple[int, ...], int],
        values: dict[int, str],
    ) -> bool:
        capture_id, record_index, positions, variables, expected = constraint
        if len(positions) == 1:
            tokens = [""]
        else:
            tokens = [values[position - 4] if 4 <= position <= 8 else fixed[position] for position in positions]
        return recovered_batch_fingerprint(capture_id, tag, record_index, tokens) == expected

    fixed_constraints = [constraint for constraint in constraints if not constraint[3]]
    if not all(evaluate_constraint(constraint, {}) for constraint in fixed_constraints):
        return []

    # Materialize each small (at most three-token) relation once.  A naive DFS
    # re-hashed the same triple millions of times for different outer choices.
    relations: list[tuple[tuple[int, ...], set[tuple[str, ...]]]] = []
    for constraint in constraints:
        variables = tuple(dict.fromkeys(constraint[3]))
        if not variables:
            continue
        allowed: set[tuple[str, ...]] = set()
        for values in product(*(domains[variable] for variable in variables)):
            assignment = dict(zip(variables, values))
            if evaluate_constraint(constraint, assignment):
                allowed.add(values)
        if not allowed:
            return []
        relations.append((variables, allowed))

    projection_indexes: list[tuple[tuple[int, ...], dict[tuple[int, ...], set[tuple[str, ...]]]]] = []
    for variables, rows in relations:
        projections: dict[tuple[int, ...], set[tuple[str, ...]]] = {}
        for mask in range(1, 1 << len(variables)):
            indexes = tuple(index for index in range(len(variables)) if mask & (1 << index))
            projections[indexes] = {
                tuple(row[index] for index in indexes)
                for row in rows
            }
        projection_indexes.append((variables, projections))

    degrees = {
        variable: sum(variable in relation[0] for relation in relations)
        for variable in range(5)
    }
    unary = {
        variable: sum(relation[0] == (variable,) for relation in relations)
        for variable in range(5)
    }
    order = sorted(range(5), key=lambda variable: (-unary[variable], -degrees[variable], variable))
    assignment: dict[int, str] = {}
    results: list[str] = []

    def compatible() -> bool:
        for variables, projections in projection_indexes:
            indexes = tuple(index for index, variable in enumerate(variables) if variable in assignment)
            if not indexes:
                continue
            values = tuple(assignment[variables[index]] for index in indexes)
            if values not in projections[indexes]:
                return False
        return True

    def search(depth: int) -> None:
        if depth == len(order):
            results.append(" ".join(assignment[index] for index in range(5)))
            return
        variable = order[depth]
        for word in domains[variable]:
            assignment[variable] = word
            if compatible():
                search(depth + 1)
        assignment.pop(variable, None)

    search(0)
    return results


def _progress(items: Iterable[T], total: int, enabled: bool) -> Iterable[T]:
    if not enabled:
        return items
    try:
        from tqdm import tqdm
        return tqdm(items, total=total, unit="phrase", desc="candidate validation")
    except ImportError:
        return items


def decrypt_with_phrases(phrases: Iterable[str], show_progress: bool) -> str:
    candidates = list(dict.fromkeys(phrases))
    blob = ENCRYPTED_FLAG_PATH.read_bytes()
    if len(blob) < 32 or blob[:4] != MAGIC:
        raise ValueError("invalid flag envelope")
    nonce, encrypted = blob[4:16], blob[16:]
    for phrase in _progress(candidates, len(candidates), show_progress):
        key = hashlib.sha256(KEY_DOMAIN + phrase.encode("utf-8")).digest()
        try:
            plaintext = AESGCM(key).decrypt(nonce, encrypted, AAD)
        except InvalidTag:
            continue
        decoded = plaintext.decode("utf-8")
        if decoded.startswith("SHA{") and decoded.endswith("}"):
            return decoded
    raise ValueError("recovery phrase not found")


def recover_flag(show_progress: bool = True) -> str:
    captures = tuple(
        extract_capture(path, server_ip)
        for path, server_ip in zip(CAPTURE_PATHS, SERVER_IPS)
    )
    overhead = derive_overhead(captures)
    candidates = candidate_secret_vectors(captures, overhead)
    if len(candidates) < 8:
        raise ValueError("insufficient administrator ambiguity")
    phrases = []
    for tag, vector in candidates:
        phrases.extend(recover_phrase_candidates(tag, vector, captures))
    if not phrases:
        raise ValueError("batch fingerprints produced no phrase candidates")
    return decrypt_with_phrases(phrases, show_progress)


def main() -> None:
    print(recover_flag(show_progress=True))


if __name__ == "__main__":
    main()
