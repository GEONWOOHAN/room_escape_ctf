import struct


def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff


def _quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)


def _block(key, counter, nonce):
    s = list(struct.unpack("<4I", b"expand 32-byte k"))
    s += list(struct.unpack("<8I", key))
    s += [counter] + list(struct.unpack("<3I", nonce))
    w = s[:]
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xffffffff for a, b in zip(s, w)])


def _stream(key, nonce, data, counter=1):
    out = bytearray()
    for pos in range(0, len(data), 64):
        block = _block(key, counter, nonce)
        counter = (counter + 1) & 0xffffffff
        out.extend(a ^ b for a, b in zip(data[pos:pos + 64], block))
    return bytes(out)


def _poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    acc = 0
    p = (1 << 130) - 5
    for pos in range(0, len(msg), 16):
        block = msg[pos:pos + 16]
        acc = ((acc + int.from_bytes(block + b"\x01", "little")) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _tag(key, nonce, aad, ciphertext):
    pad = lambda n: b"\0" * ((16 - n % 16) % 16)
    mac_data = aad + pad(len(aad)) + ciphertext + pad(len(ciphertext))
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    return _poly1305(mac_data, _block(key, 0, nonce)[:32])


def seal(key, nonce, aad, plaintext):
    ciphertext = _stream(key, nonce, plaintext)
    return ciphertext, _tag(key, nonce, aad, ciphertext)


def open_sealed(key, nonce, aad, ciphertext, tag):
    import hmac
    expected = _tag(key, nonce, aad, ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("authentication failed")
    return _stream(key, nonce, ciphertext)
