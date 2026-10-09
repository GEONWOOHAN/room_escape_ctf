#!/usr/bin/env python3
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unicodedata
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))
from crypto_core import ed25519_verify, semantic_install_receipt

HEADER = struct.Struct("<8sIIII")
MAX_PACKAGE = 4 * 1024 * 1024
MAX_ENTRY = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_package(path):
    data = path.read_bytes()
    require(len(data) <= MAX_PACKAGE and len(data) >= HEADER.size, "패키지 크기 오류")
    magic, version, manifest_size, signature_size, payload_size = HEADER.unpack_from(data)
    require(magic == b"GHOSTPKG" and version == 1, "패키지 헤더 오류")
    require(signature_size == 64 and manifest_size <= 65536 and payload_size <= 3 * 1024 * 1024, "패키지 길이 오류")
    require(HEADER.size + manifest_size + signature_size + payload_size == len(data), "패키지 잘림 또는 후행 데이터")
    cursor = HEADER.size
    manifest = data[cursor:cursor + manifest_size]; cursor += manifest_size
    signature = data[cursor:cursor + signature_size]; cursor += signature_size
    return manifest, signature, data[cursor:]


def public_key_raw():
    lines = [line for line in (ROOT / "public_key.pem").read_text().splitlines() if not line.startswith("---")]
    der = base64.b64decode("".join(lines), validate=True)
    require(len(der) == 44 and der[:12] == bytes.fromhex("302a300506032b6570032100"), "공개키 형식 오류")
    return der[-32:]


def parse_tar(payload):
    entries, cursor = [], 0
    while cursor + 512 <= len(payload):
        header = payload[cursor:cursor + 512]
        if header == bytes(512):
            require(payload[cursor:] in (bytes(len(payload) - cursor),), "TAR 종료 뒤 데이터")
            return entries
        stored = int(header[148:156].rstrip(b"\0 ") or b"0", 8)
        check = sum(header[:148]) + 8 * 32 + sum(header[156:])
        require(stored == check, "TAR 체크섬 오류")
        require(header[156:157] in (b"0", b"\0"), "일반 파일 외 TAR 엔트리 금지")
        name_bytes = header[:100].split(b"\0", 1)[0]
        prefix = header[345:500].split(b"\0", 1)[0]
        if prefix:
            name_bytes = prefix + b"/" + name_bytes
        require(name_bytes and b"\0" not in name_bytes, "TAR 경로 오류")
        try:
            name = name_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ValueError("TAR 경로 UTF-8 오류") from error
        size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
        require(size <= MAX_ENTRY and cursor + 512 + size <= len(payload), "TAR 엔트리 크기 오류")
        content = payload[cursor + 512:cursor + 512 + size]
        entries.append((name, content))
        cursor += 512 + ((size + 511) // 512) * 512
    raise ValueError("TAR 종료 블록 없음")


def shell_stage(manifest_bytes, signature, entries):
    require(ed25519_verify(public_key_raw(), manifest_bytes, signature), "Ed25519 서명 검증 실패")
    document = json.loads(manifest_bytes)
    require(document.get("device") == "gc-fleet" and document.get("version") == 18, "장치 또는 버전 불일치")
    required = document.get("required")
    require(type(required) is list and len(required) == 4, "required 목록 오류")
    hashes = {item["path"]: item["sha256"] for item in required}
    require(set(hashes) == {
        "firmware/firmware_a.bin", "firmware/firmware_b.bin",
        "firmware/firmware_c.bin", "profiles/calibration.bin",
    }, "required 경로 오류")
    optional = document.get("optional_prefix")
    require(optional == "extras/", "선택 경로 정책 오류")
    seen = set()
    for raw_path, content in entries:
        allowed = raw_path in hashes or raw_path.startswith(optional)
        require(allowed, "허용되지 않은 원시 경로")
        if raw_path in hashes:
            require(raw_path not in seen, "required 원시 경로 중복")
            require(hashlib.sha256(content).hexdigest() == hashes[raw_path], "required 해시 불일치")
            seen.add(raw_path)
    require(seen == set(hashes), "required 파일 누락")


def policy_stage(entries):
    transformed = []
    for raw_path, content in entries:
        decoded = unquote(raw_path)
        segments = decoded.split("/")
        require(".." not in segments, "직접 상위 경로 표기 금지")
        path = unicodedata.normalize("NFKC", decoded)
        while "//" in path:
            path = path.replace("//", "/")
        require(type(path) is str and "\x00" not in path and len(path.encode()) <= 500, "변환 경로 오류")
        source_class = "optional" if raw_path.startswith("extras/") else "required"
        transformed.append((source_class, path, content))
    return transformed


def extractor_path(path):
    segments = []
    for part in path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            require(bool(segments), "압축 해제 경로 오류")
            segments.pop()
            continue
        require("\\" not in part, "압축 해제 경로 오류")
        segments.append(part)
    require(bool(segments), "압축 해제 경로 오류")
    return "/".join(segments)


def extractor_stage(entries):
    work, stage = ROOT / ".update_work", ROOT / ".stage"
    for directory in (work, stage):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(mode=0o700)
    rows = []
    final_writes = []
    for index, (source_class, path, content) in enumerate(entries):
        name = f"blob-{index:03d}.bin"
        (work / name).write_bytes(content)
        rows.append(path.encode().hex() + "\t" + name)
        final_writes.append((source_class, path, extractor_path(path), content))
    (work / "entries.tsv").write_text("\n".join(rows) + "\n")
    result = subprocess.run([str(ROOT / "extractor")], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0, f"압축 해제기 거부({result.returncode})")
    calibration_writes = [item for item in final_writes if item[2] == "profiles/calibration.bin"]
    require(bool(calibration_writes), "보정 파일 설치 기록 누락")
    source_class, policy_path, final_path, content = calibration_writes[-1]
    staged = (stage / final_path).read_bytes()
    require(staged == content, "최종 보정 파일과 설치 기록 불일치")
    (stage / ".install_receipt").write_bytes(
        semantic_install_receipt(source_class, policy_path, final_path, content)
    )
    shutil.rmtree(work)


def main():
    candidate = ROOT / "candidate.pkg"
    selected = candidate if candidate.exists() else ROOT / "normal_update.pkg"
    manifest, signature, payload = read_package(selected)
    entries = parse_tar(payload)
    shell_stage(manifest, signature, entries)
    extractor_stage(policy_stage(entries))
    print("업데이트 검증 완료")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"업데이트 실패: {error}", file=sys.stderr)
        sys.exit(1)
