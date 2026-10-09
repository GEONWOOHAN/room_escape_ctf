import io
import struct
import tarfile

HEADER = struct.Struct("<8sIIII")


def make_tar(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path, content in entries:
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mode = 0o600
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def make_package(manifest, signature, payload):
    return HEADER.pack(b"GHOSTPKG", 1, len(manifest), len(signature), len(payload)) + manifest + signature + payload


def split_package(data):
    if len(data) < HEADER.size:
        raise ValueError("패키지 헤더 부족")
    magic, version, manifest_size, signature_size, payload_size = HEADER.unpack_from(data)
    if magic != b"GHOSTPKG" or version != 1:
        raise ValueError("패키지 헤더 오류")
    if HEADER.size + manifest_size + signature_size + payload_size != len(data):
        raise ValueError("패키지 길이 오류")
    cursor = HEADER.size
    manifest = data[cursor:cursor + manifest_size]; cursor += manifest_size
    signature = data[cursor:cursor + signature_size]; cursor += signature_size
    return manifest, signature, data[cursor:]
