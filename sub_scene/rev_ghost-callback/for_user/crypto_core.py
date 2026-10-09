"""워게임 파일 형식에 필요한 순수 Python 검증·AEAD 구현."""
import hashlib
import hmac
import struct


INSTALL_RECEIPT_MAGIC = b"GIR6"
INSTALL_RECEIPT_DOMAIN = b"ghost-callback-semantic-install-v6\x00"


def semantic_install_receipt(source_class, policy_path, final_path, content):
    """Bind the semantic overwrite event, not one raw TAR spelling."""
    if source_class not in ("required", "optional"):
        raise ValueError("설치 source class 오류")
    fields = (
        source_class.encode("ascii"),
        policy_path.encode("utf-8"),
        final_path.encode("utf-8"),
        hashlib.sha256(content).digest(),
    )
    material = bytearray(INSTALL_RECEIPT_DOMAIN)
    for field in fields:
        material += len(field).to_bytes(4, "little") + field
    return INSTALL_RECEIPT_MAGIC + hashlib.sha256(material).digest()


def _rol32(value, count):
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 7)


def _chacha_block(key, counter, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 키 또는 nonce 길이 오류")
    initial = list(struct.unpack("<4I", b"expand 32-byte k"))
    initial += list(struct.unpack("<8I", key))
    initial += [counter] + list(struct.unpack("<3I", nonce))
    state = initial.copy()
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12); _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14); _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15); _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13); _quarter(state, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(state, initial)])


def _xor_stream(data, key, nonce, counter=1):
    result = bytearray()
    for offset in range(0, len(data), 64):
        block = _chacha_block(key, counter, nonce)
        part = data[offset:offset + 64]
        result.extend(a ^ b for a, b in zip(part, block))
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(result)


def _poly1305(message, one_time_key):
    r = int.from_bytes(one_time_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    accumulator = 0
    prime = (1 << 130) - 5
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        accumulator = (accumulator + int.from_bytes(block + b"\x01", "little")) * r % prime
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _mac_data(aad, ciphertext):
    pad_a = bytes((-len(aad)) % 16)
    pad_c = bytes((-len(ciphertext)) % 16)
    return aad + pad_a + ciphertext + pad_c + struct.pack("<QQ", len(aad), len(ciphertext))


def aead_encrypt(key, nonce, plaintext, aad):
    ciphertext = _xor_stream(plaintext, key, nonce)
    tag = _poly1305(_mac_data(aad, ciphertext), _chacha_block(key, 0, nonce)[:32])
    return ciphertext + tag


def aead_decrypt(key, nonce, ciphertext_and_tag, aad):
    if len(ciphertext_and_tag) < 16:
        raise ValueError("암호문 길이 오류")
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    expected = _poly1305(_mac_data(aad, ciphertext), _chacha_block(key, 0, nonce)[:32])
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Poly1305 태그 검증 실패")
    return _xor_stream(ciphertext, key, nonce)


# RFC 8032 검증. 서명 생성은 제작자 환경의 cryptography를 사용한다.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = x * _I % _Q
    return x


_BY = 4 * pow(5, _Q - 2, _Q) % _Q
_BX = _xrecover(_BY)
_B = (_Q - _BX if _BX & 1 else _BX, _BY)


def _edwards_add(p, q):
    x1, y1 = p; x2, y2 = q
    denominator = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + denominator, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - denominator, _Q - 2, _Q) % _Q
    return x3, y3


def _scalar_mult(point, scalar):
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _decode_point(encoded):
    if len(encoded) != 32:
        raise ValueError("Ed25519 점 길이 오류")
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("Ed25519 비정규 점")
    x = _xrecover(y)
    if (x & 1) != (encoded[31] >> 7):
        x = _Q - x
    point = (x, y)
    if _scalar_mult(point, _L) != (0, 1):
        raise ValueError("Ed25519 부분군 오류")
    return point


def _encode_point(point):
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def ed25519_public_key(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed 길이 오류")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _encode_point(_scalar_mult(_B, scalar))


def ed25519_sign(seed, message):
    public_key = ed25519_public_key(seed)
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    encoded_r = _encode_point(_scalar_mult(_B, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % _L
    encoded_s = ((nonce + challenge * scalar) % _L).to_bytes(32, "little")
    return encoded_r + encoded_s


def ed25519_verify(public_key, message, signature):
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = _decode_point(public_key)
        r_point = _decode_point(signature[:32])
        scalar = int.from_bytes(signature[32:], "little")
        if scalar >= _L:
            return False
        challenge = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
        return _scalar_mult(_B, scalar) == _edwards_add(r_point, _scalar_mult(public_point, challenge))
    except ValueError:
        return False
