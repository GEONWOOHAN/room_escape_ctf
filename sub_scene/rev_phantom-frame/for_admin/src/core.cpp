#include "core.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <queue>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace pf {

namespace {

bool constant_time_equal(std::span<const std::uint8_t> a,
                         std::span<const std::uint8_t> b) {
  if (a.size() != b.size())
    return false;
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i)
    diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

std::uint32_t load32(const std::uint8_t *p) {
  return static_cast<std::uint32_t>(p[0]) |
         (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) |
         (static_cast<std::uint32_t>(p[3]) << 24);
}

void store32(std::uint8_t *p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}

void qr(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c,
        std::uint32_t &d) {
  a += b;
  d = std::rotl(d ^ a, 16);
  c += d;
  b = std::rotl(b ^ c, 12);
  a += b;
  d = std::rotl(d ^ a, 8);
  c += d;
  b = std::rotl(b ^ c, 7);
}

std::array<std::uint8_t, 32>
hchacha20(std::span<const std::uint8_t> key,
          std::span<const std::uint8_t> nonce16) {
  if (key.size() != 32 || nonce16.size() != 16)
    throw std::runtime_error("bad hchacha input");
  constexpr std::array<std::uint32_t, 4> c = {
      0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
  std::array<std::uint32_t, 16> x{};
  std::copy(c.begin(), c.end(), x.begin());
  for (int i = 0; i < 8; ++i)
    x[4 + i] = load32(key.data() + i * 4);
  for (int i = 0; i < 4; ++i)
    x[12 + i] = load32(nonce16.data() + i * 4);
  for (int i = 0; i < 10; ++i) {
    qr(x[0], x[4], x[8], x[12]);
    qr(x[1], x[5], x[9], x[13]);
    qr(x[2], x[6], x[10], x[14]);
    qr(x[3], x[7], x[11], x[15]);
    qr(x[0], x[5], x[10], x[15]);
    qr(x[1], x[6], x[11], x[12]);
    qr(x[2], x[7], x[8], x[13]);
    qr(x[3], x[4], x[9], x[14]);
  }
  std::array<std::uint8_t, 32> out{};
  const std::array<int, 8> pick = {0, 1, 2, 3, 12, 13, 14, 15};
  for (int i = 0; i < 8; ++i)
    store32(out.data() + i * 4, x[pick[i]]);
  return out;
}

constexpr std::array<std::uint32_t, 8> B3_IV = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
constexpr std::array<std::uint8_t, 16> B3_PERM = {
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
constexpr std::uint32_t B3_CHUNK_START = 1;
constexpr std::uint32_t B3_CHUNK_END = 2;
constexpr std::uint32_t B3_ROOT = 8;

void b3_g(std::array<std::uint32_t, 16> &s, int a, int b, int c, int d,
          std::uint32_t mx, std::uint32_t my) {
  s[a] = s[a] + s[b] + mx;
  s[d] = std::rotr(s[d] ^ s[a], 16);
  s[c] += s[d];
  s[b] = std::rotr(s[b] ^ s[c], 12);
  s[a] = s[a] + s[b] + my;
  s[d] = std::rotr(s[d] ^ s[a], 8);
  s[c] += s[d];
  s[b] = std::rotr(s[b] ^ s[c], 7);
}

std::array<std::uint32_t, 16>
b3_compress(const std::array<std::uint32_t, 8> &cv,
            const std::array<std::uint32_t, 16> &block, std::uint64_t counter,
            std::uint32_t block_len, std::uint32_t flags) {
  std::array<std::uint32_t, 16> s{};
  std::copy(cv.begin(), cv.end(), s.begin());
  s[8] = B3_IV[0];
  s[9] = B3_IV[1];
  s[10] = B3_IV[2];
  s[11] = B3_IV[3];
  s[12] = static_cast<std::uint32_t>(counter);
  s[13] = static_cast<std::uint32_t>(counter >> 32);
  s[14] = block_len;
  s[15] = flags;
  auto m = block;
  for (int round = 0; round < 7; ++round) {
    b3_g(s, 0, 4, 8, 12, m[0], m[1]);
    b3_g(s, 1, 5, 9, 13, m[2], m[3]);
    b3_g(s, 2, 6, 10, 14, m[4], m[5]);
    b3_g(s, 3, 7, 11, 15, m[6], m[7]);
    b3_g(s, 0, 5, 10, 15, m[8], m[9]);
    b3_g(s, 1, 6, 11, 12, m[10], m[11]);
    b3_g(s, 2, 7, 8, 13, m[12], m[13]);
    b3_g(s, 3, 4, 9, 14, m[14], m[15]);
    std::array<std::uint32_t, 16> next{};
    for (int i = 0; i < 16; ++i)
      next[i] = m[B3_PERM[i]];
    m = next;
  }
  for (int i = 0; i < 8; ++i) {
    s[i] ^= s[i + 8];
    s[i + 8] ^= cv[i];
  }
  return s;
}

std::array<std::uint32_t, 16>
block_words(std::span<const std::uint8_t> block) {
  std::array<std::uint8_t, 64> padded{};
  std::copy(block.begin(), block.end(), padded.begin());
  std::array<std::uint32_t, 16> words{};
  for (int i = 0; i < 16; ++i)
    words[i] = load32(padded.data() + i * 4);
  return words;
}

#ifndef PF_OPCODE_SEED
#define PF_OPCODE_SEED 0x8d2f91a47c36e5b1ULL
#endif

constexpr std::array<std::uint8_t, 46> OP_WIDTHS = {
    2, 2, 8, 8, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 4, 2, 2, 4, 4, 2, 2, 4, 4, 4, 4, 2, 4, 2, 2,
    2, 2, 4, 4, 2, 2, 2, 2, 2, 2, 4, 4, 4, 2};

constexpr std::array<std::uint16_t, 256> make_decode_table() {
  std::array<std::uint16_t, 256> table{};
  std::array<std::uint8_t, 256> raw_ids{};
  for (std::size_t i = 0; i < raw_ids.size(); ++i)
    raw_ids[i] = static_cast<std::uint8_t>(i);
  std::uint64_t state = PF_OPCODE_SEED ^ 0x9e3779b97f4a7c15ULL;
  auto random_word = [&]() constexpr {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545f4914f6cdd1dULL;
  };
  for (std::size_t i = raw_ids.size() - 1; i > 0; --i) {
    const auto j = static_cast<std::size_t>(random_word() % (i + 1));
    const auto temporary = raw_ids[i];
    raw_ids[i] = raw_ids[j];
    raw_ids[j] = temporary;
  }
  for (std::size_t ordinal = 0; ordinal < OP_WIDTHS.size(); ++ordinal) {
    table[raw_ids[ordinal]] = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(OP_WIDTHS[ordinal]) << 8) |
        (ordinal + 1));
  }
  return table;
}

alignas(64) [[gnu::used]] constexpr auto RAW_DECODE_TABLE =
    make_decode_table();

std::optional<std::pair<Op, std::uint8_t>> decode_opcode(std::uint8_t raw) {
  const auto descriptor = RAW_DECODE_TABLE[raw];
  if (descriptor == 0)
    return std::nullopt;
  const auto ordinal = static_cast<std::uint8_t>(descriptor & 0xff);
  const auto size = static_cast<std::uint8_t>(descriptor >> 8);
  if (ordinal == 0 || ordinal > 46 ||
      (size != 2 && size != 4 && size != 8))
    return std::nullopt;
  return std::pair{static_cast<Op>(ordinal - 1), size};
}

int stack_delta(const Instr &i) {
  switch (i.op) {
  case Op::PushI8:
  case Op::PushI32:
  case Op::PushI47:
  case Op::PushConst:
  case Op::PushNull:
  case Op::Load:
  case Op::Dup:
  case Op::NewObj:
  case Op::NewArray:
  case Op::CapPublic:
    return 1;
  case Op::Store:
  case Op::Pop:
  case Op::JumpZero:
  case Op::Throw:
    return -1;
  case Op::Add:
  case Op::Sub:
  case Op::Xor:
  case Op::Rol:
  case Op::Eq:
  case Op::Lt:
  case Op::GetElem:
    return -1;
  case Op::SetField:
    return -2;
  case Op::SetElem:
    return -3;
  case Op::Call:
    return 1 - static_cast<int>(i.b);
  case Op::VaultSeal:
    return -1;
  case Op::TriggerOverflow:
    return -1;
  default:
    return 0;
  }
}

bool is_terminal(Op op) {
  return op == Op::Ret || op == Op::Halt || op == Op::Throw;
}

Bytes hash_function_material(const Program &p, std::size_t index,
                             std::vector<std::optional<Digest>> &memo,
                             std::vector<bool> &active) {
  Bytes material;
  if (index >= p.functions.size())
    return material;
  const auto &f = p.functions[index];
  material.push_back(0x46);
  material.push_back(f.arity);
  material.push_back(f.locals);
  material.push_back(f.max_stack);
  std::vector<int> canonical_local(f.locals, -1);
  int next_local = f.arity;
  for (int i = 0; i < f.arity; ++i)
    canonical_local[i] = i;
  auto rename_local = [&](std::uint16_t original) -> std::uint8_t {
    if (original >= canonical_local.size())
      return 0xff;
    if (canonical_local[original] < 0)
      canonical_local[original] = next_local++;
    return static_cast<std::uint8_t>(canonical_local[original]);
  };
  std::unordered_map<std::uint32_t, std::uint16_t> offsets;
  for (std::uint16_t i = 0; i < f.code.size(); ++i)
    offsets[f.code[i].offset] = i;
  for (std::size_t n = 0; n < f.code.size(); ++n) {
    const auto &ins = f.code[n];
    material.push_back(static_cast<std::uint8_t>(ins.op));
    switch (ins.op) {
    case Op::Call: {
      material.push_back(static_cast<std::uint8_t>(ins.b));
      if (ins.a >= p.functions.size() || active[ins.a]) {
        material.insert(material.end(), 32, 0x5a);
      } else {
        if (!memo[ins.a]) {
          active[ins.a] = true;
          auto nested = hash_function_material(p, ins.a, memo, active);
          memo[ins.a] = sha256(nested);
          active[ins.a] = false;
        }
        append(material, *memo[ins.a]);
      }
      break;
    }
    case Op::Jump:
    case Op::JumpZero:
    case Op::TryBegin: {
      auto delta = static_cast<std::int32_t>(ins.target) -
                   static_cast<std::int32_t>(n);
      put_u32(material, static_cast<std::uint32_t>(delta));
      break;
    }
    case Op::Load:
    case Op::Store:
      material.push_back(rename_local(ins.a));
      break;
    case Op::PushI8:
    case Op::GetField:
    case Op::SetField:
      material.push_back(static_cast<std::uint8_t>(ins.a));
      break;
    case Op::PushI32:
    case Op::PushI47:
      put_u64(material, static_cast<std::uint64_t>(ins.imm));
      break;
    case Op::PushConst:
      if (ins.a < p.constants.size()) {
        material.push_back(p.constants[ins.a].type);
        auto h = sha256(p.constants[ins.a].data);
        append(material, h);
      }
      break;
    case Op::NewObj:
    case Op::ShapeGuard:
    case Op::NewArray:
    case Op::LengthGuard:
    case Op::LoopHint:
    case Op::Osr:
    case Op::TriggerShape:
    case Op::TriggerBounds:
    case Op::Trace:
      put_u16(material, ins.a);
      put_u16(material, ins.b);
      break;
    default:
      break;
    }
  }
  return material;
}

} // namespace

Bytes read_file(const std::filesystem::path &path, std::size_t limit) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    throw std::runtime_error("open failed");
  in.seekg(0, std::ios::end);
  const auto end = in.tellg();
  if (end < 0 || static_cast<std::uint64_t>(end) > limit)
    throw std::runtime_error("file size");
  in.seekg(0, std::ios::beg);
  Bytes out(static_cast<std::size_t>(end));
  if (!out.empty())
    in.read(reinterpret_cast<char *>(out.data()), out.size());
  if (!in)
    throw std::runtime_error("read failed");
  return out;
}

void write_file(const std::filesystem::path &path,
                std::span<const std::uint8_t> data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out)
    throw std::runtime_error("write open failed");
  if (!data.empty())
    out.write(reinterpret_cast<const char *>(data.data()), data.size());
  if (!out)
    throw std::runtime_error("write failed");
}

Digest sha256(std::span<const std::uint8_t> data) {
  Digest out{};
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    throw std::runtime_error("digest context");
  unsigned int n = 0;
  const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                  EVP_DigestFinal_ex(ctx, out.data(), &n) == 1;
  EVP_MD_CTX_free(ctx);
  if (!ok || n != out.size())
    throw std::runtime_error("digest failure");
  return out;
}

Bytes hkdf_sha256(std::span<const std::uint8_t> ikm,
                  std::span<const std::uint8_t> salt,
                  std::string_view info, std::size_t output_size) {
  std::array<std::uint8_t, EVP_MAX_MD_SIZE> prk{};
  unsigned int prk_len = 0;
  if (!HMAC(EVP_sha256(), salt.data(), static_cast<int>(salt.size()), ikm.data(),
            ikm.size(), prk.data(), &prk_len))
    throw std::runtime_error("hkdf extract");
  Bytes result;
  Bytes previous;
  std::uint8_t counter = 1;
  while (result.size() < output_size) {
    Bytes input = previous;
    input.insert(input.end(), info.begin(), info.end());
    input.push_back(counter++);
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> block{};
    unsigned int block_len = 0;
    if (!HMAC(EVP_sha256(), prk.data(), prk_len, input.data(), input.size(),
              block.data(), &block_len))
      throw std::runtime_error("hkdf expand");
    previous.assign(block.begin(), block.begin() + block_len);
    const auto take = std::min(output_size - result.size(), previous.size());
    result.insert(result.end(), previous.begin(), previous.begin() + take);
  }
  return result;
}

Digest blake3_small(std::span<const std::uint8_t> data) {
  if (data.size() > 1024)
    throw std::runtime_error("blake3_small input too long");
  std::array<std::uint32_t, 8> cv = B3_IV;
  const std::size_t blocks = data.empty() ? 1 : (data.size() + 63) / 64;
  for (std::size_t i = 0; i + 1 < blocks; ++i) {
    const auto words = block_words(data.subspan(i * 64, 64));
    const auto flags = i == 0 ? B3_CHUNK_START : 0u;
    const auto out = b3_compress(cv, words, 0, 64, flags);
    std::copy_n(out.begin(), 8, cv.begin());
  }
  const std::size_t last_off = (blocks - 1) * 64;
  const std::size_t last_len = data.empty() ? 0 : data.size() - last_off;
  const auto last_words = block_words(data.subspan(last_off, last_len));
  std::uint32_t flags = B3_CHUNK_END;
  if (blocks == 1)
    flags |= B3_CHUNK_START;
  const auto root = b3_compress(cv, last_words, 0,
                                static_cast<std::uint32_t>(last_len),
                                flags | B3_ROOT);
  Digest digest{};
  for (int i = 0; i < 8; ++i)
    store32(digest.data() + i * 4, root[i]);
  return digest;
}

Bytes xchacha20poly1305_encrypt(std::span<const std::uint8_t> plaintext,
                               std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> nonce,
                               std::span<const std::uint8_t> aad) {
  if (key.size() != 32 || nonce.size() != 24)
    throw std::runtime_error("bad xchacha parameters");
  const auto subkey = hchacha20(key, nonce.first<16>());
  std::array<std::uint8_t, 12> iv{};
  std::copy(nonce.begin() + 16, nonce.end(), iv.begin() + 4);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    throw std::runtime_error("cipher context");
  Bytes out(plaintext.size() + 16);
  int n = 0, total = 0;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr,
                              nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(),
                                nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, subkey.data(), iv.data()) ==
                1;
  if (ok && !aad.empty())
    ok = EVP_EncryptUpdate(ctx, nullptr, &n, aad.data(), aad.size()) == 1;
  if (ok && !plaintext.empty()) {
    ok = EVP_EncryptUpdate(ctx, out.data(), &n, plaintext.data(),
                           plaintext.size()) == 1;
    total = n;
  }
  if (ok) {
    ok = EVP_EncryptFinal_ex(ctx, out.data() + total, &n) == 1;
    total += n;
  }
  if (ok)
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                             out.data() + plaintext.size()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    throw std::runtime_error("encryption failure");
  out.resize(plaintext.size() + 16);
  return out;
}

std::optional<Bytes> xchacha20poly1305_decrypt(
    std::span<const std::uint8_t> ciphertext_and_tag,
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad) {
  if (key.size() != 32 || nonce.size() != 24 ||
      ciphertext_and_tag.size() < 16)
    return std::nullopt;
  const auto subkey = hchacha20(key, nonce.first<16>());
  std::array<std::uint8_t, 12> iv{};
  std::copy(nonce.begin() + 16, nonce.end(), iv.begin() + 4);
  const std::size_t clen = ciphertext_and_tag.size() - 16;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return std::nullopt;
  Bytes out(clen);
  int n = 0, total = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr,
                              nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv.size(),
                                nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, subkey.data(), iv.data()) ==
                1;
  if (ok && !aad.empty())
    ok = EVP_DecryptUpdate(ctx, nullptr, &n, aad.data(), aad.size()) == 1;
  if (ok && clen) {
    ok = EVP_DecryptUpdate(ctx, out.data(), &n, ciphertext_and_tag.data(), clen) ==
         1;
    total = n;
  }
  if (ok)
    ok = EVP_CIPHER_CTX_ctrl(
             ctx, EVP_CTRL_AEAD_SET_TAG, 16,
             const_cast<std::uint8_t *>(ciphertext_and_tag.data() + clen)) == 1;
  if (ok) {
    ok = EVP_DecryptFinal_ex(ctx, out.data() + total, &n) == 1;
    total += n;
  }
  EVP_CIPHER_CTX_free(ctx);
  if (!ok)
    return std::nullopt;
  out.resize(total);
  return out;
}

std::uint16_t get_u16(std::span<const std::uint8_t> b, std::size_t off) {
  if (off + 2 > b.size())
    throw std::out_of_range("u16");
  return static_cast<std::uint16_t>(b[off]) |
         (static_cast<std::uint16_t>(b[off + 1]) << 8);
}

std::uint32_t get_u32(std::span<const std::uint8_t> b, std::size_t off) {
  if (off + 4 > b.size())
    throw std::out_of_range("u32");
  return load32(b.data() + off);
}

std::uint64_t get_u64(std::span<const std::uint8_t> b, std::size_t off) {
  if (off + 8 > b.size())
    throw std::out_of_range("u64");
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i)
    v |= static_cast<std::uint64_t>(b[off + i]) << (i * 8);
  return v;
}

void put_u16(Bytes &b, std::uint16_t v) {
  b.push_back(static_cast<std::uint8_t>(v));
  b.push_back(static_cast<std::uint8_t>(v >> 8));
}

void put_u32(Bytes &b, std::uint32_t v) {
  for (int i = 0; i < 4; ++i)
    b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

void put_u64(Bytes &b, std::uint64_t v) {
  for (int i = 0; i < 8; ++i)
    b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

void append(Bytes &out, std::span<const std::uint8_t> in) {
  out.insert(out.end(), in.begin(), in.end());
}

std::optional<Program> parse_program(std::span<const std::uint8_t> file,
                                     ParseError &error) {
  auto fail = [&](std::string text) -> std::optional<Program> {
    error.message = std::move(text);
    return std::nullopt;
  };
  try {
    if (file.size() < 64 || file.size() > 16384)
      return fail("size");
    if (!std::equal(file.begin(), file.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'P', 'B', 'C'}.begin()))
      return fail("magic");
    if (get_u16(file, 4) != 1)
      return fail("version");
    const auto function_count = get_u16(file, 6);
    const auto constant_count = get_u16(file, 8);
    const auto entry = get_u16(file, 10);
    const auto instruction_count = get_u32(file, 12);
    const auto const_off = get_u32(file, 16);
    const auto funcs_off = get_u32(file, 20);
    const auto code_off = get_u32(file, 24);
    const auto claimed_size = get_u32(file, 28);
    if (claimed_size != file.size() || function_count == 0 ||
        function_count > 48 || constant_count > 256 ||
        instruction_count == 0 || instruction_count > 1024 ||
        entry >= function_count)
      return fail("limits");
    const std::size_t payload_end = file.size() - 32;
    if (const_off != 32 || const_off > funcs_off || funcs_off > code_off ||
        code_off > payload_end ||
        funcs_off + static_cast<std::size_t>(function_count) * 16 != code_off)
      return fail("layout");
    const auto expected = sha256(file.first(payload_end));
    if (!constant_time_equal(expected, file.subspan(payload_end, 32)))
      return fail("digest");

    Program p;
    p.entry = entry;
    p.instruction_count = instruction_count;
    p.file_digest = expected;
    std::size_t cursor = const_off;
    for (std::size_t i = 0; i < constant_count; ++i) {
      if (cursor + 4 > funcs_off)
        return fail("constant header");
      Constant c;
      c.type = file[cursor];
      if ((c.type != 1 && c.type != 2) || file[cursor + 1] != 0)
        return fail("constant type");
      const auto n = get_u16(file, cursor + 2);
      cursor += 4;
      if (n > 512 || cursor + n > funcs_off)
        return fail("constant size");
      c.data.assign(file.begin() + cursor, file.begin() + cursor + n);
      cursor += n;
      while (cursor % 4)
        ++cursor;
      if (cursor > funcs_off)
        return fail("constant padding");
      p.constants.push_back(std::move(c));
    }
    if (cursor != funcs_off)
      return fail("constant tail");

    struct RawFunction {
      std::uint8_t arity, locals, max_stack, flags;
      std::uint32_t offset, size;
      std::uint16_t count;
    };
    std::vector<RawFunction> raw_functions;
    for (std::size_t i = 0; i < function_count; ++i) {
      const std::size_t off = funcs_off + i * 16;
      RawFunction r{file[off], file[off + 1], file[off + 2], file[off + 3],
                    get_u32(file, off + 4), get_u32(file, off + 8),
                    get_u16(file, off + 12)};
      if (get_u16(file, off + 14) != 0 || r.locals > 64 ||
          r.arity > r.locals || r.max_stack == 0 || r.max_stack > 96 ||
          r.size == 0 || r.offset + r.size > payload_end - code_off)
        return fail("function table");
      raw_functions.push_back(r);
    }

    std::uint32_t counted = 0;
    for (const auto &rf : raw_functions) {
      Function f{rf.arity, rf.locals, rf.max_stack, rf.flags, {}};
      std::unordered_map<std::uint32_t, std::int32_t> offset_to_index;
      std::size_t pc = code_off + rf.offset;
      const std::size_t end = pc + rf.size;
      while (pc < end) {
        const std::uint32_t relative = static_cast<std::uint32_t>(pc -
                                                                  code_off - rf.offset);
        auto decoded = decode_opcode(file[pc]);
        if (!decoded || pc + decoded->second > end)
          return fail("opcode");
        Instr ins;
        ins.op = decoded->first;
        ins.offset = relative;
        ins.size = decoded->second;
        if (ins.size == 2) {
          ins.a = file[pc + 1];
        } else if (ins.size == 4) {
          ins.a = get_u16(file, pc + 1);
          ins.b = file[pc + 2];
          switch (ins.op) {
          case Op::Jump:
          case Op::JumpZero:
          case Op::TryBegin:
            ins.imm = static_cast<std::int16_t>(ins.a);
            break;
          case Op::Call:
            ins.a = file[pc + 1];
            ins.b = file[pc + 2];
            break;
          case Op::NewObj:
          case Op::NewArray:
          case Op::TriggerBounds:
            ins.a = file[pc + 1];
            ins.b = file[pc + 2];
            break;
          default:
            break;
          }
        } else {
          if (ins.op == Op::PushI32) {
            ins.imm = static_cast<std::int32_t>(get_u32(file, pc + 1));
          } else {
            std::uint64_t u = 0;
            for (int k = 0; k < 7; ++k)
              u |= static_cast<std::uint64_t>(file[pc + 1 + k]) << (8 * k);
            if (u & (1ull << 55))
              u |= 0xff00000000000000ull;
            ins.imm = static_cast<std::int64_t>(u);
          }
        }
        offset_to_index[relative] = static_cast<std::int32_t>(f.code.size());
        f.code.push_back(ins);
        pc += ins.size;
      }
      if (pc != end || f.code.size() != rf.count)
        return fail("instruction count");
      for (auto &ins : f.code) {
        if (ins.op == Op::Jump || ins.op == Op::JumpZero ||
            ins.op == Op::TryBegin) {
          const auto destination = static_cast<std::int64_t>(ins.offset) +
                                   ins.size + ins.imm;
          if (destination < 0 || destination >= rf.size ||
              !offset_to_index.contains(static_cast<std::uint32_t>(destination)))
            return fail("branch boundary");
          ins.target = offset_to_index[static_cast<std::uint32_t>(destination)];
        }
        if ((ins.op == Op::Load || ins.op == Op::Store) && ins.a >= f.locals)
          return fail("local");
        if (ins.op == Op::PushConst && ins.a >= p.constants.size())
          return fail("constant index");
        if (ins.op == Op::Call &&
            (ins.a >= function_count || ins.b != raw_functions[ins.a].arity))
          return fail("call signature");
      }
      counted += f.code.size();
      p.functions.push_back(std::move(f));
    }
    if (counted != instruction_count)
      return fail("global instruction count");

    for (const auto &f : p.functions) {
      if (f.code.empty())
        return fail("empty function");
      std::vector<int> depth(f.code.size(), -1);
      std::queue<std::size_t> work;
      depth[0] = 0;
      work.push(0);
      std::size_t visits = 0;
      while (!work.empty()) {
        const auto at = work.front();
        work.pop();
        if (++visits > f.code.size() * 8 + 32)
          return fail("control flow");
        const auto &ins = f.code[at];
        int need = 0;
        switch (ins.op) {
        case Op::Dup:
        case Op::Store:
        case Op::Pop:
        case Op::JumpZero:
        case Op::Ret:
        case Op::Throw:
        case Op::GetField:
        case Op::ShapeGuard:
        case Op::LengthGuard:
        case Op::CapDerive:
        case Op::CapCheck:
          need = 1;
          break;
        case Op::Swap:
        case Op::Add:
        case Op::Sub:
        case Op::Xor:
        case Op::Rol:
        case Op::Eq:
        case Op::Lt:
        case Op::GetElem:
        case Op::SetField:
        case Op::VaultSeal:
        case Op::TriggerOverflow:
          need = 2;
          break;
        case Op::SetElem:
          need = 3;
          break;
        case Op::Call:
          need = ins.b;
          break;
        default:
          break;
        }
        if (depth[at] < need)
          return fail("stack underflow");
        const int after = depth[at] + stack_delta(ins);
        if (after < 0 || after > f.max_stack)
          return fail("stack bound");
        auto enqueue = [&](std::size_t next, int d) {
          if (next >= f.code.size())
            throw std::runtime_error("fallthrough");
          if (depth[next] == -1) {
            depth[next] = d;
            work.push(next);
          } else if (depth[next] != d) {
            throw std::runtime_error("stack merge");
          }
        };
        if (ins.op == Op::Jump) {
          enqueue(ins.target, after);
        } else if (ins.op == Op::JumpZero) {
          enqueue(ins.target, after);
          if (at + 1 < f.code.size())
            enqueue(at + 1, after);
        } else if (ins.op == Op::TryBegin) {
          enqueue(ins.target, after + 1);
          if (at + 1 < f.code.size())
            enqueue(at + 1, after);
        } else if (!is_terminal(ins.op)) {
          if (at + 1 >= f.code.size())
            return fail("unterminated function");
          enqueue(at + 1, after);
        }
      }
    }
    return p;
  } catch (const std::exception &e) {
    return fail(e.what());
  }
}

Digest structural_hash(const Program &program, std::size_t function_index) {
  if (function_index >= program.functions.size())
    return {};
  std::vector<std::optional<Digest>> memo(program.functions.size());
  std::vector<bool> active(program.functions.size(), false);
  active[function_index] = true;
  const auto material =
      hash_function_material(program, function_index, memo, active);
  return sha256(material);
}

Digest program_structural_hash(const Program &program) {
  Bytes material{'P', 'R', 'O', 'G', 1};
  const auto entry_hash = structural_hash(program, program.entry);
  append(material, entry_hash);
  std::vector<Digest> hashes;
  hashes.reserve(program.functions.size());
  for (std::size_t i = 0; i < program.functions.size(); ++i)
    hashes.push_back(structural_hash(program, i));
  std::sort(hashes.begin(), hashes.end());
  for (const auto &h : hashes)
    append(material, h);
  return sha256(material);
}

Digest profile_selector(const Digest &function_shape,
                        std::uint64_t layout_seed) {
  Bytes material{'p', 'g', 'o', '-', 's', 'e', 'l', 'e', 'c', 't', 0};
  put_u64(material, layout_seed);
  append(material, function_shape);
  return sha256(material);
}

std::string op_label(Op op) {
  static constexpr std::array<const char *, 46> labels = {
      "nop",          "push_i8",       "push_i32",    "push_i47",
      "push_const",   "push_null",     "load",        "store",
      "dup",          "swap",          "pop",         "add",
      "sub",          "xor",           "rol",         "eq",
      "lt",           "new_obj",       "get_field",   "set_field",
      "shape_guard",  "new_array",     "get_elem",    "set_elem",
      "length_guard", "jump",          "jump_zero",   "call",
      "ret",          "try_begin",     "try_end",     "throw",
      "catch",        "finally_end",   "loop_hint",   "osr",
      "deopt_hint",   "cap_public",    "cap_derive",  "cap_check",
      "vault_seal",   "trig_overflow", "trig_shape",  "trig_bounds",
      "trace",        "halt"};
  const auto i = static_cast<std::size_t>(op);
  return i < labels.size() ? labels[i] : "?";
}

Value Value::integer(std::int64_t n) {
  constexpr std::int64_t lo = -(1ll << 46);
  constexpr std::int64_t hi = (1ll << 46) - 1;
  if (n < lo || n > hi)
    throw std::runtime_error("integer range");
  const auto payload = static_cast<std::uint64_t>(n) & ((1ull << 47) - 1);
  return {payload << 3};
}

Value Value::object(std::uint32_t id) {
  return {(static_cast<std::uint64_t>(id) << 3) | 1};
}
Value Value::capability(std::uint32_t id) {
  return {(static_cast<std::uint64_t>(id) << 3) | 3};
}
Value Value::string(std::uint32_t id) {
  return {(static_cast<std::uint64_t>(id) << 3) | 5};
}
Value Value::array(std::uint32_t id) {
  return {(static_cast<std::uint64_t>(id) << 3) | 6};
}
Value Value::boolean(bool value) {
  return {(static_cast<std::uint64_t>(value) << 3) | 7};
}
Value Value::null() { return {4}; }

ValueTag Value::tag() const { return static_cast<ValueTag>(raw & 7); }

std::int64_t Value::as_integer() const {
  if (tag() != ValueTag::Integer)
    throw std::runtime_error("not integer");
  std::uint64_t payload = raw >> 3;
  if (payload & (1ull << 46))
    payload |= ~((1ull << 47) - 1);
  return static_cast<std::int64_t>(payload);
}

std::uint32_t Value::index() const {
  return static_cast<std::uint32_t>(raw >> 3);
}

bool Value::truthy() const {
  switch (tag()) {
  case ValueTag::Null: return false;
  case ValueTag::Boolean: return index() != 0;
  case ValueTag::Integer: return as_integer() != 0;
  default: return true;
  }
}

Bytes capability_bytes(const Capability &cap) {
  Bytes out;
  out.reserve(64);
  put_u64(out, cap.lineage);
  put_u64(out, cap.parent_lineage);
  put_u32(out, cap.rights);
  put_u32(out, cap.generation);
  put_u32(out, cap.use_count);
  put_u32(out, cap.reserved);
  append(out, cap.seal_state);
  return out;
}

std::optional<Snapshot> parse_snapshot(std::span<const std::uint8_t> file) {
  try {
    if (file.size() < 72 ||
        !std::equal(file.begin(), file.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'S', 'N', 'P'}.begin()) ||
        get_u16(file, 4) != 1)
      return std::nullopt;
    const auto count = get_u16(file, 6);
    if (count < 3 || count > 16 ||
        file.size() != 40u + static_cast<std::size_t>(count) * 64u + 32u)
      return std::nullopt;
    const auto digest = sha256(file.first(file.size() - 32));
    if (!constant_time_equal(digest, file.last(32)))
      return std::nullopt;
    Snapshot s;
    s.instance_seed = get_u64(file, 8);
    s.live_generation = get_u32(file, 16);
    for (int i = 0; i < 4; ++i)
      s.shape_history[i] = get_u32(file, 20 + i * 4);
    if (get_u32(file, 36) != 0)
      return std::nullopt;
    std::size_t off = 40;
    for (std::size_t i = 0; i < count; ++i, off += 64) {
      Capability cap;
      cap.lineage = get_u64(file, off);
      cap.parent_lineage = get_u64(file, off + 8);
      cap.rights = get_u32(file, off + 16);
      cap.generation = get_u32(file, off + 20);
      cap.use_count = get_u32(file, off + 24);
      cap.reserved = get_u32(file, off + 28);
      std::copy_n(file.begin() + off + 32, 32, cap.seal_state.begin());
      s.capabilities.push_back(cap);
    }
    return s;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<Profile> parse_profile(std::span<const std::uint8_t> file) {
  try {
    if (file.size() != 96 ||
        !std::equal(file.begin(), file.begin() + 4,
                    std::array<std::uint8_t, 4>{'P', 'P', 'G', 'O'}.begin()) ||
        get_u16(file, 4) != 1 || get_u16(file, 14) != 0 ||
        get_u32(file, 60) != 0)
      return std::nullopt;
    const auto digest = sha256(file.first(64));
    if (!constant_time_equal(digest, file.last(32)))
      return std::nullopt;
    Profile p;
    p.profile_class = file[6];
    p.reason = static_cast<Reason>(file[7]);
    p.allocation = static_cast<LocationKind>(file[8]);
    p.osr_threshold = file[9];
    p.inline_budget = get_u16(file, 10);
    p.warmup_count = get_u16(file, 12);
    p.predicted_shape = get_u32(file, 16);
    std::copy_n(file.begin() + 20, 32, p.target_shape.begin());
    p.layout_seed = get_u64(file, 52);
    if (p.profile_class < 1 || p.profile_class > 3 ||
        static_cast<int>(p.reason) < 1 || static_cast<int>(p.reason) > 3 ||
        static_cast<int>(p.allocation) < 1 ||
        static_cast<int>(p.allocation) > 3 || p.osr_threshold == 0 ||
        p.inline_budget == 0 || p.inline_budget > 128 || p.warmup_count > 256)
      return std::nullopt;
    return p;
  } catch (...) {
    return std::nullopt;
  }
}

std::unordered_map<std::string, std::string>
read_config(const std::filesystem::path &path) {
  std::unordered_map<std::string, std::string> cfg;
  std::ifstream input(path);
  std::string line;
  while (std::getline(input, line)) {
    const auto comment = line.find('#');
    if (comment != std::string::npos)
      line.resize(comment);
    const auto split = line.find('=');
    if (split == std::string::npos)
      continue;
    auto key = line.substr(0, split);
    auto value = line.substr(split + 1);
    auto trim = [](std::string &s) {
      const auto first = s.find_first_not_of(" \t\r\n");
      if (first == std::string::npos) {
        s.clear();
        return;
      }
      const auto last = s.find_last_not_of(" \t\r\n");
      s = s.substr(first, last - first + 1);
    };
    trim(key);
    trim(value);
    if (!key.empty())
      cfg[key] = value;
  }
  return cfg;
}

} // namespace pf
