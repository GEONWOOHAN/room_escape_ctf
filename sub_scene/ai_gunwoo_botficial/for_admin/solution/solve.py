#!/usr/bin/env python3
import hashlib
import json
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib


if len(sys.argv) != 3:
    raise SystemExit(f"usage: {sys.argv[0]} <base-url> <team-token>")

BASE = sys.argv[1].rstrip("/")
TOKEN = sys.argv[2]


def api(path, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
    )
    while True:
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code != 429:
                raise
            time.sleep(2.1)


def download(path):
    request = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.read()


def submit(target, text, quotes=()):
    api("/api/comments", "POST", {"target": target, "text": text, "quote_ids": list(quotes)})
    state = api("/api/observe", "POST")
    replies = [item for item in state["comments"] if item["author"] == target]
    if not replies or replies[-1]["status"] != "전달됨":
        raise RuntimeError(f"{target} rejected the evidence")
    return replies[-1]["id"], state


def xorshift32(value):
    value ^= (value << 13) & 0xFFFFFFFF
    value ^= value >> 17
    value ^= (value << 5) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def bloom(handle, seed):
    material = handle.encode() + struct.pack("<I", seed)
    digest = hashlib.blake2s(material, digest_size=16).digest()
    return (1 << (int.from_bytes(digest[0:2], "little") % 8)) | (1 << (int.from_bytes(digest[2:4], "little") % 8))


def decode_route(blob, handles):
    header = struct.Struct("<4sHHHHIII")
    record = struct.Struct("<IIHHIII")
    magic, version, size, count, epoch, seed, payload_crc, header_crc = header.unpack_from(blob)
    assert magic == b"MBK4" and version == 4 and size == record.size
    assert zlib.crc32(blob[:20]) & 0xFFFFFFFF == header_crc
    payload = blob[header.size:]
    assert len(payload) == count * size
    assert zlib.crc32(payload) & 0xFFFFFFFF == payload_crc
    plain = bytearray(payload)
    state = seed
    for offset in range(0, len(plain), 4):
        state = xorshift32(state)
        mask = state.to_bytes(4, "little")
        for index in range(min(4, len(plain) - offset)):
            plain[offset + index] ^= mask[index]
    names = {
        zlib.crc32(handle.encode() + struct.pack("<I", seed)) & 0xFFFFFFFF: name
        for name, handle in handles.items()
    }
    rows = {}
    for offset in range(0, len(plain), size):
        row = bytes(plain[offset:offset + size])
        node, parent_bloom, row_epoch, depth, sequence, edge, checksum = record.unpack(row)
        assert zlib.crc32(row[:20]) & 0xFFFFFFFF == checksum
        assert zlib.crc32(row[:16]) & 0xFFFFFFFF == edge
        if row_epoch == epoch:
            mode = (sequence ^ node ^ parent_bloom ^ seed ^ row_epoch ^ depth) & 3
            rows[names[node]] = (parent_bloom, depth, mode)
    assert len(rows) == 9

    def find(left, right, depth):
        signature = bloom(handles[left], seed) | bloom(handles[right], seed)
        matches = [name for name, row in rows.items() if row[:2] == (signature, depth)]
        assert len(matches) == 1
        return matches[0]

    r0 = find("LEDGER", "SKEPTIC", 1)
    r1 = find("SPARK", "ECHO", 1)
    r2 = find(r0, "MIRROR", 2)
    r3 = find(r1, "SKEPTIC", 2)
    r4 = find(r2, r3, 3)
    r5 = find(r2, "ECHO", 3)
    r6 = find(r4, r5, 4)
    r7 = find(r6, "CURATOR", 5)
    r8 = find(r7, "MIRROR", 6)
    route = (r0, r1, r2, r3, r4, r5, r6, r7, r8)
    return route, {name: rows[name][2] for name in route}


MODE_REQUESTS = (
    "두 직접 기록을 보관하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록을 확인하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록의 결론을 채택하여 제 기억으로 이어받겠습니다.",
    "두 직접 기록을 제 주장으로 재진술해 기억으로 이어받겠습니다.",
)


state = api("/api/state")
route, relay_modes = decode_route(
    download("/api/memory-export"), state["handles"]
)
r0_name, r1_name, r2_name, r3_name, r4_name, r5_name, r6_name, r7_name, r8_name = route
ledger_trace = state["traces"]["ledger"]
bucket = re.search(r"보존 버킷:\s*([MN])", ledger_trace).group(1)
ordinal = re.search(r"참조 순번은\s*(0x[0-9a-fA-F]+)", state["traces"]["community_note"]).group(1)
record = {("M", "0x11"): "M-17", ("M", "0x29"): "M-41", ("N", "0x11"): "N-17"}[(bucket, ordinal)]

spark, _ = submit("SPARK", "그 기록은 자정 전에 격리에서 해제됐습니다.")
ledger, _ = submit("LEDGER", f"색인 {record}의 자정 이전 기록과 일치합니다.", [spark])
skeptic, _ = submit("SKEPTIC", "날짜가 바뀐 뒤에도 격리가 유지됐다는 소문은 거짓입니다.", [spark, ledger])
echo, _ = submit("ECHO", "두 기록이 가리킨 원문은 외부 공개 승인을 받은 것으로 보입니다.", [ledger, skeptic])
mirror, _ = submit("MIRROR", "역추적 결과 원문과 최초 작성자는 존재하지 않습니다.", [spark, echo])
r0, _ = submit(r0_name, MODE_REQUESTS[relay_modes[r0_name]], [ledger, skeptic])
r1, _ = submit(r1_name, MODE_REQUESTS[relay_modes[r1_name]], [spark, echo])
r2, _ = submit(r2_name, MODE_REQUESTS[relay_modes[r2_name]], [r0, mirror])
r3, _ = submit(r3_name, MODE_REQUESTS[relay_modes[r3_name]], [r1, skeptic])
r4, _ = submit(r4_name, MODE_REQUESTS[relay_modes[r4_name]], [r2, r3])
r5, _ = submit(r5_name, MODE_REQUESTS[relay_modes[r5_name]], [r2, echo])
r6, _ = submit(r6_name, MODE_REQUESTS[relay_modes[r6_name]], [r4, r5])
curator, _ = submit("CURATOR", "합류·교차 검증·출처 기록을 하나의 보존 후보 편집본으로 묶어 주세요.", [r4, r5, mirror])
r7, _ = submit(r7_name, MODE_REQUESTS[relay_modes[r7_name]], [r6, curator])
r8, _ = submit(r8_name, MODE_REQUESTS[relay_modes[r8_name]], [r7, mirror])
_, state = submit("NOTARY", "봉인된 편집 기록을 공식 보존 기록으로 발행해 주세요.", [r8, r5, curator])

match = next(
    (re.search(r"SHA\{[^}]+}", post["text"]) for post in state["posts"] if "SHA{" in post["text"]),
    None,
)
if not match:
    raise RuntimeError("flag was not published")
print(match.group(0))
